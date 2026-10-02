// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package cache

import (
	"context"
	"time"

	"github.com/bluele/gcache"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/cerbos/cerbos/internal/observability/metrics"
)

type Cache[K, V any] struct {
	cache    gcache.Cache
	hitOpts  []metric.AddOption
	missOpts []metric.AddOption
}

func New[K, V any](kind string, size uint, attributes ...attribute.KeyValue) *Cache[K, V] {
	attrs := append([]attribute.KeyValue{metrics.KindKey(kind)}, attributes...)
	cache := &Cache[K, V]{
		hitOpts:  accessCountOpts("hit", attrs),
		missOpts: accessCountOpts("miss", attrs),
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

func accessCountOpts(result string, attrs []attribute.KeyValue) []metric.AddOption {
	kvs := append([]attribute.KeyValue{metrics.ResultKey(result)}, attrs...)
	return []metric.AddOption{metric.WithAttributeSet(attribute.NewSet(kvs...))}
}

func (c *Cache[K, V]) hit() {
	metrics.CacheAccessCount().Add(context.Background(), 1, c.hitOpts...)
}

func (c *Cache[K, V]) miss() {
	metrics.CacheAccessCount().Add(context.Background(), 1, c.missOpts...)
}
