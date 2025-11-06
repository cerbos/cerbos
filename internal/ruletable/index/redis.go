package index

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/redis/go-redis/v9"
)

const (
	keyTTL = time.Minute * 5
)

var (
	_ Index      = (*Redis)(nil)
	_ literalMap = (*RedisLiteralMap)(nil)
	_ globMap    = (*RedisGlobMap)(nil)
)

type Redis struct {
	db    *redis.Client
	nsKey string
}

func NewRedis(client *redis.Client, namespace string) (*Redis, error) {
	return &Redis{
		db:    client,
		nsKey: namespace,
	}, nil
}

func (r *Redis) getLiteralMap(category string) literalMap {
	return newRedisLiteralMap(r.db, r.nsKey, category)
}

func (r *Redis) getGlobMap(category string) globMap {
	return newRedisGlobMap(r.db, r.nsKey, category)
}

func (r *Redis) resolve(ctx context.Context, rows []*Row) ([]*Row, error) {
	sums := make([]string, 0, len(rows))
	for _, row := range rows {
		var sum string
		if row.RuleTable_RuleRow != nil {
			sum = string(hex.EncodeToString(row.sum[:]))
		} else {
			sum = r.rowKey(hex.EncodeToString(row.sum[:]))
		}
		sums = append(sums, sum)
	}

	if len(sums) == 0 {
		return rows, nil
	}

	rawRows, err := r.db.MGet(ctx, sums...).Result()
	if err != nil {
		return nil, err
	}

	for i, raw := range rawRows {
		if rows[i].RuleTable_RuleRow == nil {
			rows[i].RuleTable_RuleRow = &runtimev1.RuleTable_RuleRow{}
			if err := rows[i].UnmarshalVT([]byte(raw.(string))); err != nil {
				return nil, err
			}
			if err := hydrateParams(rows[i]); err != nil {
				return nil, err
			}
		}
	}

	return rows, nil
}

func (r *Redis) rowKey(sum string) string {
	// value is the serialised row
	return r.nsKey + ":" + sum
}

type redisMap struct {
	db     *redis.Client
	nsKey  string
	catKey string
}

func newRedisMap(db *redis.Client, namespace, categoryKey string) *redisMap {
	return &redisMap{
		db:     db,
		nsKey:  namespace,
		catKey: namespace + ":" + categoryKey,
	}
}

func (rm *redisMap) sumsKey(categoryItem string) string {
	// values consist of sets of checksums mapped to individual rows
	return rm.catKey + ":" + categoryItem
}

func (rm *redisMap) catFromSumsKey(k string) string {
	return strings.TrimPrefix(k, rm.catKey+":")
}

func (rm *redisMap) rowKey(sum string) string {
	// value is the serialised row
	return rm.nsKey + ":" + sum
}

func (rm *redisMap) sumFromRowKey(key string) string {
	return strings.TrimPrefix(key, rm.nsKey+":")
}

/*
nsKey == {namespace}
catKey == {nsKey:category}

We store the following:
- {catKey} -> set[{catKey:category_item}] e.g. `1:scope:foo`
- {catKey:category_item} -> set[{namespace:row_checksum}]
- {nsKey:row_checksum} -> *Ruletable_RuleRow
// scoping checksums by namespace prevents duplicating rows across categories)
*/
func (rm *redisMap) set(ctx context.Context, cat string, rs *rowSet) error {
	sumsKey := rm.sumsKey(cat)
	_, err := rm.db.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.SAdd(ctx, rm.catKey, sumsKey)

		sums, rows, err := serialize(rs, rm.rowKey)
		if err != nil {
			return err
		}

		p.SAdd(ctx, sumsKey, sums...)

		rkBatch := []any{}
		for i, r := range rows {
			rk := sums[i].(string)
			rkBatch = append(rkBatch, rk, r)
		}

		// TODO(saml) how to deal with TTL on these keys?
		if err := rm.db.MSet(ctx, rkBatch...).Err(); err != nil {
			return err
		}

		// TODO(saml)
		p.Expire(ctx, sumsKey, keyTTL)
		p.Expire(ctx, rm.catKey, keyTTL)

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (rm *redisMap) get(ctx context.Context, cats ...string) (map[string]*rowSet, error) {
	res := make(map[string]*rowSet)
	for _, cat := range cats {
		sumsKey := rm.sumsKey(cat)

		ok, err := rm.db.SIsMember(ctx, rm.catKey, sumsKey).Result()
		if err != nil {
			return nil, err
		}
		if !ok {
			return res, nil
		}

		sums, err := rm.db.SMembers(ctx, sumsKey).Result()
		if err != nil {
			return nil, err
		}

		rs, err := getRowSetWithSums(sums, rm.sumFromRowKey)
		if err != nil {
			return nil, err
		}

		res[cat] = rs
	}

	return res, nil
}

func (rm *redisMap) getAll(ctx context.Context) (map[string]*rowSet, error) {
	catsKeys, err := rm.db.SMembers(ctx, rm.catKey).Result()
	if err != nil {
		return nil, err
	}

	res := make(map[string]*rowSet)
	for _, catKey := range catsKeys {
		sums, err := rm.db.SMembers(ctx, catKey).Result()
		if err != nil {
			return nil, err
		}

		rs, err := getRowSetWithSums(sums, rm.sumFromRowKey)
		if err != nil {
			return nil, err
		}

		res[rm.catFromSumsKey(catKey)] = rs
	}

	return res, nil
}

type RedisLiteralMap struct {
	*redisMap
}

func newRedisLiteralMap(db *redis.Client, namespace, category string) *RedisLiteralMap {
	return &RedisLiteralMap{
		redisMap: newRedisMap(db, namespace, category),
	}
}

type RedisGlobMap struct {
	*redisMap
}

func newRedisGlobMap(db *redis.Client, namespace, category string) *RedisGlobMap {
	return &RedisGlobMap{
		redisMap: newRedisMap(db, namespace, category),
	}
}

func (gl *RedisGlobMap) getWithLiteral(ctx context.Context, keys ...string) (map[string]*rowSet, error) {
	return gl.redisMap.get(ctx, keys...)
}

func (gl *RedisGlobMap) getMerged(ctx context.Context, keys ...string) (map[string]*rowSet, error) {
	catsKeys, err := gl.db.SMembers(ctx, gl.catKey).Result()
	if err != nil {
		return nil, err
	}

	matched := make(map[string][]string, len(keys))
	for _, catKey := range catsKeys {
		cat := gl.catFromSumsKey(catKey)
		for _, k := range keys {
			if cat == k || util.MatchesGlob(cat, k) {
				matched[k] = append(matched[k], catKey)
			}
		}
	}

	res := make(map[string]*rowSet, len(keys))
	sumCmds := make(map[string]*redis.StringSliceCmd, len(keys))
	if _, err = gl.db.Pipelined(ctx, func(p redis.Pipeliner) error {
		for _, k := range keys {
			matchingCatItems := matched[k]
			switch len(matchingCatItems) {
			case 0:
			case 1:
				sumCmds[k] = p.SMembers(ctx, matchingCatItems[0])
			default:
				sumCmds[k] = p.SUnion(ctx, matchingCatItems...)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	sumsMap := make(map[string][]string, len(keys))
	rowCmds := make(map[string]*redis.SliceCmd, len(keys))
	if _, err = gl.db.Pipelined(ctx, func(p redis.Pipeliner) error {
		for k := range matched {
			sums, err := sumCmds[k].Result()
			if err != nil {
				return err
			}
			rowCmds[k] = p.MGet(ctx, sums...)
			sumsMap[k] = sums
		}
		return nil
	}); err != nil {
		return nil, err
	}

	for k := range matched {
		rs, err := getRowSetWithSums(sumsMap[k], gl.sumFromRowKey)
		if err != nil {
			return nil, err
		}
		res[k] = rs
	}

	return res, nil
}

func serialize(rs *rowSet, sumsFn func(string) string) ([]any, []any, error) {
	sums := make([]any, 0, len(rs.m))
	raws := make([]any, 0, len(rs.m))
	for sum, r := range rs.m {
		sums = append(sums, sumsFn(hex.EncodeToString(sum[:])))
		b, err := r.MarshalVT()
		if err != nil {
			return nil, nil, err
		}
		raws = append(raws, b)
	}
	return sums, raws, nil
}

func getRowSetWithSums(sums []string, sumsFn func(string) string) (*rowSet, error) {
	rs := newRowSet()
	for i := range sums {
		b, err := hex.DecodeString(sumsFn(sums[i]))
		if err != nil {
			panic(err)
		}
		var sum [32]byte
		copy(sum[:], b)

		rs.set(&Row{
			sum: sum,
		})
	}
	return rs, nil
}

func hydrateParams(r *Row) error {
	var err error
	if (r.PolicyKind == policyv1.Kind_KIND_RESOURCE && !r.FromRolePolicy) ||
		r.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
		r.Params, err = GenerateRowParams(r.OriginFqn, r.RuleTable_RuleRow.Params.OrderedVariables, r.RuleTable_RuleRow.Params.Constants)
		if err != nil {
			return err
		}
	}
	if r.RuleTable_RuleRow.DerivedRoleParams != nil {
		r.DerivedRoleParams, err = GenerateRowParams(namer.DerivedRolesFQN(r.OriginDerivedRole), r.RuleTable_RuleRow.DerivedRoleParams.OrderedVariables, r.RuleTable_RuleRow.DerivedRoleParams.Constants)
		if err != nil {
			return err
		}
	}
	return nil
}
