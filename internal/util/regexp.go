// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"regexp"
	"sync"
)

type RegexpCache struct {
	cache map[string]*regexp.Regexp
	mu    sync.RWMutex
}

func NewRegexpCache() *RegexpCache {
	return &RegexpCache{
		cache: make(map[string]*regexp.Regexp),
	}
}

// GetCompiledExpr lazily compiles (and stores) regexp.
func (c *RegexpCache) GetCompiledExpr(re string) (*regexp.Regexp, error) {
	c.mu.RLock()
	r, ok := c.cache[re]
	c.mu.RUnlock()

	if !ok {
		var err error
		if r, err = regexp.Compile(re); err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %s", re)
		}

		c.mu.Lock()
		c.cache[re] = r
		c.mu.Unlock()
	}

	return r, nil
}
