// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"time"

	"go.uber.org/multierr"

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

func (c *Conf) Validate() (outErr error) {
	if c.CacheSize != 0 {
		util.DeprecationWarning("compile.cacheSize")
		outErr = multierr.Append(outErr, errors.New("compile.cacheSize section is no longer supported"))
	}

	if c.CacheDuration != 0 {
		util.DeprecationWarning("compile.cacheDuration")
		outErr = multierr.Append(outErr, errors.New("compile.cacheDuration section is no longer supported"))
	}

	return outErr
}
