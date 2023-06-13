// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"regexp"
	"sync"
)

type RegexpCache struct {
	cache map[string]*regexp.Regexp
	mu    *sync.Mutex
}

func NewRegexpCache() *RegexpCache {
	return &RegexpCache{
		cache: make(map[string]*regexp.Regexp),
		mu:    &sync.Mutex{},
	}
}

// GetCompiledExpr lazily compiles (and stores) regexp.
func (c *RegexpCache) GetCompiledExpr(re string) (*regexp.Regexp, error) {
	if c.cache == nil {
		c.cache = make(map[string]*regexp.Regexp)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	r, ok := c.cache[re]
	if !ok {
		var err error
		if r, err = regexp.Compile(re); err != nil {
			return nil, err
		}
		c.cache[re] = r
	}

	return r, nil
}
