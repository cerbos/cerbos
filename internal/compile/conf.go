// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"time"
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
