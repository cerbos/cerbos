// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
	"time"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/redis/go-redis/v9"
)

const (
	// expirationBuffer is the safety margin between the sentinel expiring and the data expiring.
	// This guarantees that if `GetExistingRedis` returns successfully, the data keys will persist for at least
	// this long, covering the duration of the read operation.
	defaultKeyTTL           = time.Minute * 5
	defaultExpirationBuffer = time.Minute * 1
	sentinelSuffix          = "sentinel"
)

var (
	_ Index      = (*Redis)(nil)
	_ literalMap = (*RedisLiteralMap)(nil)
	_ globMap    = (*RedisGlobMap)(nil)

	ErrCacheMiss = errors.New("index not found in cache")
	ErrReadOnly  = errors.New("redis instance is read only")
)

// Cmdable is a subset of the builtin redis.Cmdable interface.
type Cmdable interface {
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	MGet(ctx context.Context, keys ...string) *redis.SliceCmd
	SMembers(ctx context.Context, key string) *redis.StringSliceCmd

	Pipelined(ctx context.Context, fn func(redis.Pipeliner) error) ([]redis.Cmder, error)
	TxPipelined(ctx context.Context, fn func(redis.Pipeliner) error) ([]redis.Cmder, error)
}

type Redis struct {
	sentinelDeadline time.Time
	dataDeadline     time.Time
	db               Cmdable
	nsKey            string
	sentKey          string
	readOnly         bool
}

// GetExistingRedis checks if a valid index exists for the given namespace.
// It checks for the presence of the sentinel key.
//   - If the sentinel exists, it returns a valid *Redis adapter ready for reading.
//   - If the sentinel is missing, it returns (nil, ErrCacheMiss), signaling the caller to use New().
func GetExistingRedis(ctx context.Context, client Cmdable, namespace string) (*Redis, error) {
	sentKey := namespace + ":" + sentinelSuffix
	exists, err := client.Exists(ctx, sentKey).Result()
	if err != nil {
		return nil, err
	}

	if exists == 0 {
		return nil, ErrCacheMiss
	}

	return &Redis{
		db:       client,
		nsKey:    namespace + ":",
		sentKey:  sentKey,
		readOnly: true,
	}, nil
}

// NewRedis creates a new index generation.
// All data written via this instance will share these exact timestamps, ensuring the entire
// batch expires consistently with no time drift.
//
// Usage: Call this when GetExisting returns ErrCacheMiss.
func NewRedis(client Cmdable, namespace string, ttl, expirationBuffer time.Duration) *Redis {
	if ttl <= 0 {
		ttl = defaultKeyTTL
	}
	if expirationBuffer <= 0 {
		expirationBuffer = defaultExpirationBuffer
	}

	now := time.Now()
	sentinelDeadline := now.Add(ttl)
	dataDeadline := sentinelDeadline.Add(expirationBuffer)

	return &Redis{
		db:               client,
		nsKey:            namespace + ":",
		sentKey:          namespace + ":" + sentinelSuffix,
		sentinelDeadline: sentinelDeadline,
		dataDeadline:     dataDeadline,
	}
}

func (r *Redis) GetExpiresAt() time.Time {
	return r.dataDeadline
}

func (r *Redis) getLiteralMap(category CategoryKey) literalMap {
	return newRedisLiteralMap(r.db, r.nsKey, string(category), r.sentKey, r.readOnly, r.sentinelDeadline, r.dataDeadline)
}

func (r *Redis) getGlobMap(category CategoryKey) globMap {
	return newRedisGlobMap(r.db, r.nsKey, string(category), r.sentKey, r.readOnly, r.sentinelDeadline, r.dataDeadline)
}

func (r *Redis) resolve(ctx context.Context, rows []*Row) ([]*Row, error) {
	sums := make([]string, 0, len(rows))
	for _, row := range rows {
		var sum string
		if row.RuleTable_RuleRow != nil {
			sum = strconv.FormatUint(row.sum, 10)
		} else {
			sum = r.rowKey(row.sum)
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
			if raw == nil {
				// If we reach this case, somethings gone unexpectedly wrong.
				return nil, fmt.Errorf("data missing for row checksum %s", sums[i])
			}
			rows[i].RuleTable_RuleRow = &runtimev1.RuleTable_RuleRow{}
			if err := rows[i].UnmarshalVT([]byte(raw.(string))); err != nil { //nolint:forcetypeassert
				return nil, err
			}
			if err := hydrateParams(rows[i]); err != nil {
				return nil, err
			}
		}
	}

	return rows, nil
}

func (r *Redis) needsResolve() bool {
	return true
}

func (r *Redis) resolveIter(ctx context.Context, rows iter.Seq[*Row]) (iter.Seq[*Row], error) {
	resolved, err := r.resolve(ctx, slices.Collect(rows))
	if err != nil {
		return nil, err
	}
	return slices.Values(resolved), nil
}

func (r *Redis) rowKey(sum uint64) string {
	// value is the serialised row
	return r.nsKey + strconv.FormatUint(sum, 10)
}

type redisMap struct {
	sentinelDeadline time.Time
	dataDeadline     time.Time
	db               Cmdable
	nsKey            string
	catKey           string
	sentKey          string
	readOnly         bool
}

func newRedisMap(db Cmdable, nsKey, categoryKey, sentKey string, readOnly bool, sentinelDeadline, dataDeadline time.Time) *redisMap {
	return &redisMap{
		db:               db,
		nsKey:            nsKey,
		catKey:           nsKey + categoryKey,
		sentKey:          sentKey,
		sentinelDeadline: sentinelDeadline,
		dataDeadline:     dataDeadline,
		readOnly:         readOnly,
	}
}

func (rm *redisMap) sumsKey(categoryItem string) string {
	// values consist of sets of checksums mapped to individual rows
	return rm.catKey + ":" + categoryItem
}

func (rm *redisMap) catFromSumsKey(k string) string {
	return strings.TrimPrefix(k, rm.catKey+":")
}

func (rm *redisMap) serialize(rs *rowSet) ([]any, []any, error) {
	sums := make([]any, 0, len(rs.m))
	raws := make([]any, 0, len(rs.m))
	for sum, r := range rs.m {
		sums = append(sums, rm.rowKey(sum))
		b, err := r.MarshalVT()
		if err != nil {
			return nil, nil, err
		}
		raws = append(raws, b)
	}
	return sums, raws, nil
}

func (rm *redisMap) rowKey(sum uint64) string {
	// value is the serialised row
	return rm.nsKey + strconv.FormatUint(sum, 10)
}

func (rm *redisMap) sumFromRowKey(key string) uint64 {
	s := strings.TrimPrefix(key, rm.nsKey)
	sum, _ := strconv.ParseUint(s, 10, 64)
	return sum
}

func (rm *redisMap) getRowSetWithSums(sums []string) *rowSet {
	rs := newRowSet()
	for i := range sums {
		rs.set(&Row{
			sum: rm.sumFromRowKey(sums[i]),
		})
	}
	return rs
}

/*
nsKey == {namespace}
catKey == {nsKey:category}

We store the following:
- {catKey} -> set[{catKey:category_item}] e.g. `1:scope:foo`
- {catKey:category_item} -> set[{namespace:row_checksum}]
- {nsKey:row_checksum} -> *Ruletable_RuleRow
// scoping checksums by namespace prevents duplicating rows across categories).
*/
func (rm *redisMap) set(ctx context.Context, cat string, rs *rowSet) error {
	if rm.readOnly {
		return ErrReadOnly
	}

	sums, rows, err := rm.serialize(rs)
	if err != nil {
		return err
	}

	sumsKey := rm.sumsKey(cat)

	_, err = rm.db.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.SAdd(ctx, rm.catKey, sumsKey)
		p.PExpireAt(ctx, rm.catKey, rm.dataDeadline)

		p.SAdd(ctx, sumsKey, sums...)
		p.PExpireAt(ctx, sumsKey, rm.dataDeadline)

		for i, r := range rows {
			rk := sums[i].(string) //nolint:forcetypeassert
			p.Set(ctx, rk, r, 0)
			p.PExpireAt(ctx, rk, rm.dataDeadline)
		}

		p.Set(ctx, rm.sentKey, "1", 0)
		p.PExpireAt(ctx, rm.sentKey, rm.sentinelDeadline)

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (rm *redisMap) setBatch(ctx context.Context, batch map[string]*rowSet) error {
	if len(batch) == 0 {
		return nil
	}

	if rm.readOnly {
		return ErrReadOnly
	}

	_, err := rm.db.TxPipelined(ctx, func(p redis.Pipeliner) error {
		for cat, rs := range batch {
			sums, rows, err := rm.serialize(rs)
			if err != nil {
				return err
			}

			sumsKey := rm.sumsKey(cat)

			p.SAdd(ctx, rm.catKey, sumsKey)
			p.PExpireAt(ctx, rm.catKey, rm.dataDeadline)

			p.SAdd(ctx, sumsKey, sums...)
			p.PExpireAt(ctx, sumsKey, rm.dataDeadline)

			for i, r := range rows {
				rk := sums[i].(string) //nolint:forcetypeassert
				p.Set(ctx, rk, r, 0)
				p.PExpireAt(ctx, rk, rm.dataDeadline)
			}
		}

		p.Set(ctx, rm.sentKey, "1", 0)
		p.PExpireAt(ctx, rm.sentKey, rm.sentinelDeadline)

		return nil
	})

	return err
}

func (rm *redisMap) get(ctx context.Context, cats ...string) (map[string]*rowSet, error) {
	if len(cats) == 0 {
		return nil, nil
	}

	existsCmds := make(map[string]*redis.BoolCmd, len(cats))
	dataCmds := make(map[string]*redis.StringSliceCmd, len(cats))

	_, err := rm.db.Pipelined(ctx, func(p redis.Pipeliner) error {
		for _, cat := range cats {
			sumsKey := rm.sumsKey(cat)
			existsCmds[cat] = p.SIsMember(ctx, rm.catKey, sumsKey)
			dataCmds[cat] = p.SMembers(ctx, sumsKey)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	res := make(map[string]*rowSet)
	for _, cat := range cats {
		if existsCmds[cat].Val() {
			sums := dataCmds[cat].Val()
			if len(sums) > 0 {
				res[cat] = rm.getRowSetWithSums(sums)
			}
		}
	}

	return res, nil
}

func (rm *redisMap) getAll(ctx context.Context) (map[string]*rowSet, error) {
	catsKeys, err := rm.db.SMembers(ctx, rm.catKey).Result()
	if err != nil {
		return nil, err
	}

	if len(catsKeys) == 0 {
		return make(map[string]*rowSet), nil
	}

	cmds := make(map[string]*redis.StringSliceCmd, len(catsKeys))
	_, err = rm.db.Pipelined(ctx, func(p redis.Pipeliner) error {
		for _, catKey := range catsKeys {
			cmds[catKey] = p.SMembers(ctx, catKey)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	res := make(map[string]*rowSet, len(catsKeys))
	for _, catKey := range catsKeys {
		sums := cmds[catKey].Val()
		catName := rm.catFromSumsKey(catKey)
		res[catName] = rm.getRowSetWithSums(sums)
	}

	return res, nil
}

func (rm *redisMap) getAllKeys(ctx context.Context) ([]string, error) {
	catsKeys, err := rm.db.SMembers(ctx, rm.catKey).Result()
	if err != nil {
		return nil, err
	}

	res := make([]string, len(catsKeys))
	for i, catKey := range catsKeys {
		res[i] = rm.catFromSumsKey(catKey)
	}

	return res, nil
}

func (rm *redisMap) delete(ctx context.Context, cats ...string) error {
	if len(cats) == 0 {
		return nil
	}

	targetKeys := make([]string, len(cats))
	targetMembers := make([]any, len(cats))

	for i, cat := range cats {
		key := rm.sumsKey(cat)
		targetKeys[i] = key
		targetMembers[i] = key
	}

	_, err := rm.db.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.SRem(ctx, rm.catKey, targetMembers...)
		p.Del(ctx, targetKeys...)
		return nil
	})

	return err
}

type RedisLiteralMap struct {
	*redisMap
}

func newRedisLiteralMap(db Cmdable, nsKey, category, sentKey string, readOnly bool, sentinelDeadline, dataDeadline time.Time) *RedisLiteralMap {
	return &RedisLiteralMap{
		redisMap: newRedisMap(db, nsKey, category, sentKey, readOnly, sentinelDeadline, dataDeadline),
	}
}

type RedisGlobMap struct {
	*redisMap
}

func newRedisGlobMap(db Cmdable, nsKey, category, sentKey string, readOnly bool, sentinelDeadline, dataDeadline time.Time) *RedisGlobMap {
	return &RedisGlobMap{
		redisMap: newRedisMap(db, nsKey, category, sentKey, readOnly, sentinelDeadline, dataDeadline),
	}
}

func (gl *RedisGlobMap) getWithLiteral(ctx context.Context, keys ...string) (map[string]*rowSet, error) {
	return gl.get(ctx, keys...)
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

	for k := range matched {
		if cmd, ok := sumCmds[k]; ok {
			sums, err := cmd.Result()
			if err != nil {
				return nil, err
			}
			res[k] = gl.getRowSetWithSums(sums)
		} else {
			res[k] = newRowSet()
		}
	}

	return res, nil
}

func hydrateParams(r *Row) error {
	var err error
	if (r.PolicyKind == policyv1.Kind_KIND_RESOURCE && !r.FromRolePolicy) ||
		r.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
		r.Params, err = generateRowParams(r.OriginFqn, r.RuleTable_RuleRow.Params.OrderedVariables, r.RuleTable_RuleRow.Params.Constants)
		if err != nil {
			return err
		}
	}
	if r.RuleTable_RuleRow.DerivedRoleParams != nil {
		r.DerivedRoleParams, err = generateRowParams(namer.DerivedRolesFQN(r.OriginDerivedRole), r.RuleTable_RuleRow.DerivedRoleParams.OrderedVariables, r.RuleTable_RuleRow.DerivedRoleParams.Constants)
		if err != nil {
			return err
		}
	}
	return nil
}
