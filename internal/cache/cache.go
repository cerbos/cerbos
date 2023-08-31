// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"time"

	"github.com/bluele/gcache"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
)

type Cache[K, V any] struct {
	cache gcache.Cache
	config
}

type config struct {
	tagMutators []tag.Mutator
}

type Option func(*config)

func WithTags(mutators ...tag.Mutator) Option {
	return func(conf *config) {
		conf.tagMutators = mutators
	}
}

func New[K, V any](kind string, size uint, options ...Option) *Cache[K, V] {
	cache := &Cache[K, V]{}

	for _, option := range options {
		option(&cache.config)
	}

	cache.tagMutators = append(cache.tagMutators, tag.Upsert(metrics.KeyCacheKind, kind))

	_ = stats.RecordWithTags(context.Background(),
		cache.tagMutators,
		metrics.CacheMaxSize.M(int64(size)),
	)

	gauge := metrics.MakeCacheGauge(kind)
	cache.cache = gcache.
		New(int(size)).
		ARC().
		AddedFunc(func(_, _ any) {
			gauge.Add(1)
		}).
		EvictedFunc(func(_, _ any) {
			gauge.Add(-1)
		}).
		Build()

	return cache
}

func (c *Cache[K, V]) Has(k K) bool {
	return c.cache.Has(k)
}

func (c *Cache[K, V]) Get(k K) (V, bool) {
	var zero V

	entry, err := c.cache.GetIFPresent(k)
	if err == nil {
		v, ok := entry.(V)
		if ok {
			c.hit()
			return v, true
		}
	}

	c.miss()
	return zero, false
}

func (c *Cache[K, V]) Set(k K, v V) {
	_ = c.cache.Set(k, v)
}

func (c *Cache[K, V]) SetWithExpire(k K, v V, expiry time.Duration) {
	_ = c.cache.SetWithExpire(k, v, expiry)
}

func (c *Cache[K, V]) Remove(k K) bool {
	return c.cache.Remove(k)
}

func (c *Cache[K, V]) Purge() {
	c.cache.Purge()
}

func (c *Cache[K, V]) hit() {
	_ = stats.RecordWithTags(context.Background(),
		append(c.tagMutators, tag.Upsert(metrics.KeyCacheResult, "hit")),
		metrics.CacheAccessCount.M(1),
	)
}

func (c *Cache[K, V]) miss() {
	_ = stats.RecordWithTags(context.Background(),
		append(c.tagMutators, tag.Upsert(metrics.KeyCacheResult, "miss")),
		metrics.CacheAccessCount.M(1),
	)
}
