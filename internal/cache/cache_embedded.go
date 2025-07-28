// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package cache

import (
	"time"

	"github.com/bluele/gcache"
)

type Cache[K, V any] struct {
	cache gcache.Cache
}

func New[K, V any](kind string, size uint, _ ...any) *Cache[K, V] {
	cache := &Cache[K, V]{}
	cache.cache = gcache.
		New(int(size)).
		ARC().
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
			return v, true
		}
	}

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
