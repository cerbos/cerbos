// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

const (
	confKey          = "compile"
	defaultCacheSize = 1024
)

// Conf is optional configuration for caches.
type Conf struct {
	// CacheSize is the number of compiled policies to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",example=1024"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.CacheSize = defaultCacheSize
}

// DefaultConf creates a config with defaults.
func DefaultConf() *Conf {
	cconf := &Conf{}
	cconf.SetDefaults()

	return cconf
}
