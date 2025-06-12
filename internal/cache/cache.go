// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"time"

	"github.com/bluele/gcache"
	"go.opentelemetry.io/otel/attribute"

	"github.com/cerbos/cerbos/internal/observability/metrics"
)

type Cache[K comparable, V any] struct {
	cache     gcache.Cache
	hitAttrs  []attribute.KeyValue
	missAttrs []attribute.KeyValue
}

func New[K comparable, V any](kind string, size uint, attributes ...attribute.KeyValue) *Cache[K, V] {
	attrs := append([]attribute.KeyValue{metrics.KindKey(kind)}, attributes...)
	cache := &Cache[K, V]{
		hitAttrs:  append([]attribute.KeyValue{metrics.ResultKey("hit")}, attrs...),
		missAttrs: append([]attribute.KeyValue{metrics.ResultKey("miss")}, attrs...),
	}

	metrics.Add(context.Background(), metrics.CacheMaxSize(), int64(size), attrs...)
	cache.cache = gcache.
		New(int(size)).
		ARC().
		AddedFunc(func(_, _ any) {
			metrics.Add(context.Background(), metrics.CacheLiveObjGauge(), 1, attrs...)
		}).
		EvictedFunc(func(_, _ any) {
			metrics.Add(context.Background(), metrics.CacheLiveObjGauge(), -1, attrs...)
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

func (c *Cache[K, V]) CopyFromMap(m map[K]V, expiry time.Duration) {
	for k, v := range m {
		c.SetWithExpire(k, v, expiry)
	}
}

func (c *Cache[K, V]) Len() int {
	return c.cache.Len(false)
}

func (c *Cache[K, V]) hit() {
	metrics.Inc(context.Background(), metrics.CacheAccessCount(), c.hitAttrs...)
}

func (c *Cache[K, V]) miss() {
	metrics.Inc(context.Background(), metrics.CacheAccessCount(), c.missAttrs...)
}
