package index

import (
	"context"
	"crypto/sha256"
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
	db        *redis.Client
	namespace string
}

func NewRedis(client *redis.Client, namespace string) (*Redis, error) {
	return &Redis{
		db:        client,
		namespace: namespace,
	}, nil
}

func (r *Redis) getNamespace() string {
	return r.namespace
}

func (r *Redis) getLiteralMap(category string) literalMap {
	return newRedisLiteralMap(r.db, r.namespace, category)
}

func (r *Redis) getGlobMap(category string) globMap {
	return newRedisGlobMap(r.db, r.namespace, category)
}

type redisMap struct {
	db  *redis.Client
	key string
}

func newRedisMap(db *redis.Client, namespace, categoryKey string) *redisMap {
	return &redisMap{
		db:  db,
		key: namespace + ":" + categoryKey,
	}
}

func (rm *redisMap) rowsKey(k string) string {
	return rm.key + ":" + k
}

func (rm *redisMap) catFromRowsKey(k string) string {
	return strings.TrimPrefix(k, rm.key+":")
}

/*
We store the following:
(`idxKey` == {namespace:category})
- {idxKey} -> set[{idxKey:category_item}] e.g. `1:scope:foo`
- {idxKey:category_item} -> set[*Ruletable_RuleRow]
*/
func (rm *redisMap) set(ctx context.Context, cat string, rs *rowSet) error {
	rowsKey := rm.rowsKey(cat)
	_, err := rm.db.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.SAdd(ctx, rm.key, rowsKey)

		rows, err := serialize(rs)
		if err != nil {
			return err
		}
		p.SAdd(ctx, rowsKey, rows...)

		p.Expire(ctx, rowsKey, keyTTL)
		p.Expire(ctx, rm.key, keyTTL)

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
		rowsKey := rm.rowsKey(cat)

		ok, err := rm.db.SIsMember(ctx, rm.key, rowsKey).Result()
		if err != nil {
			return nil, err
		}
		if !ok {
			return res, nil
		}

		rawRows, err := rm.db.SMembers(ctx, rowsKey).Result()
		if err != nil {
			return nil, err
		}

		rs, err := deserialize(rawRows)
		if err != nil {
			return nil, err
		}

		res[cat] = rs
	}

	return res, nil
}

func (rm *redisMap) getAll(ctx context.Context) (map[string]*rowSet, error) {
	rowsKeys, err := rm.db.SMembers(ctx, rm.key).Result()
	if err != nil {
		return nil, err
	}

	res := make(map[string]*rowSet)
	for _, rk := range rowsKeys {
		rawRows, err := rm.db.SMembers(ctx, rk).Result()
		if err != nil {
			return nil, err
		}

		rs, err := deserialize(rawRows)
		if err != nil {
			return nil, err
		}

		res[rm.catFromRowsKey(rk)] = rs
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
	rowsKeys, err := gl.db.SMembers(ctx, gl.key).Result()
	if err != nil {
		return nil, err
	}

	res := make(map[string]*rowSet)
	for _, key := range keys {
		resRs := newRowSet()
		for _, rk := range rowsKeys {
			cat := gl.catFromRowsKey(rk)
			if cat != key && !util.MatchesGlob(cat, key) {
				continue
			}

			rawRows, err := gl.db.SMembers(ctx, rk).Result()
			if err != nil {
				return nil, err
			}

			rs, err := deserialize(rawRows)
			if err != nil {
				return nil, err
			}

			resRs = resRs.unionWith(rs)
		}
		res[key] = resRs
	}

	return res, nil
}

func serialize(rs *rowSet) ([]any, error) {
	res := make([]any, 0, len(rs.m))
	for _, r := range rs.m {
		b, err := r.MarshalVT()
		if err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, nil
}

func deserialize(raws []string) (*rowSet, error) {
	// TODO(saml) move the sum to the proto definition
	rowHasher := sha256.New()
	rs := newRowSet()
	for _, s := range raws {
		r := &runtimev1.RuleTable_RuleRow{}
		if err := r.UnmarshalVT([]byte(s)); err != nil {
			return nil, err
		}

		r.HashPB(rowHasher, ignoredRuleTableProtoFields)
		var sum [sha256.Size]byte
		rowHasher.Sum(sum[:0])
		rowHasher.Reset()

		params, drParams, err := hydrateParams(r)
		if err != nil {
			return nil, err
		}

		rs.set(&Row{
			RuleTable_RuleRow: r,
			sum:               sum,
			Params:            params,
			DerivedRoleParams: drParams,
		})
	}
	return rs, nil
}

func hydrateParams(rr *runtimev1.RuleTable_RuleRow) (*rowParams, *rowParams, error) {
	var params, drParams *rowParams
	var err error
	if (rr.PolicyKind == policyv1.Kind_KIND_RESOURCE && !rr.FromRolePolicy) ||
		rr.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
		params, err = GenerateRowParams(rr.OriginFqn, rr.Params.OrderedVariables, rr.Params.Constants)
		if err != nil {
			return nil, nil, err
		}
	}
	if rr.DerivedRoleParams != nil {
		drParams, err = GenerateRowParams(namer.DerivedRolesFQN(rr.OriginDerivedRole), rr.DerivedRoleParams.OrderedVariables, rr.DerivedRoleParams.Constants)
		if err != nil {
			return nil, nil, err
		}
	}
	return params, drParams, nil
}
