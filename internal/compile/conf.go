// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"time"

	"go.uber.org/multierr"
)

const (
	confKey          = "compile"
	defaultCacheSize = 1024
)

// Conf is optional configuration for caches.
type Conf struct {
	// CacheSize is the number of compiled policies to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",example=1024"`
	// CacheDuration is the duration to cache an entry.
	CacheDuration time.Duration `yaml:"cacheDuration" conf:",example=60s"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.CacheSize = defaultCacheSize
}

func (c *Conf) Validate() (outErr error) {
	if c.CacheSize < 1 {
		outErr = multierr.Append(outErr, errors.New("compile.cacheSize must be greater than 0"))
	}

	if c.CacheDuration < 0 {
		outErr = multierr.Append(outErr, errors.New("compile.cacheDuration must be positive"))
	}

	return outErr
}

// DefaultConf creates a config with defaults.
func DefaultConf() *Conf {
	cconf := &Conf{}
	cconf.SetDefaults()

	return cconf
}
