// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"time"

	"github.com/cerbos/cerbos/internal/util"
)

const confKey = "compile"

// Conf is optional configuration for caches.
type Conf struct {
	// [DEPRECATED] CacheSize is the number of compiled policies to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",ignore"`
	// [DEPRECATED] CacheDuration is the duration to cache an entry.
	CacheDuration time.Duration `yaml:"cacheDuration" conf:",ignore"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {}

func (c *Conf) Validate() error {
	if c.CacheSize != 0 {
		util.DeprecationWarning("compile.cacheSize")
	}

	if c.CacheDuration != 0 {
		util.DeprecationWarning("compile.cacheDuration")
	}

	return nil
}
