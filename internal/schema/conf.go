// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import "github.com/cerbos/cerbos/internal/config"

const (
	confKey            = "schema"
	defaultEnforcement = EnforcementNone
	defaultCacheSize   = 1024
)

// Conf is optional configuration for schema validation.
type Conf struct {
	// Enforcement defines level of the validations. Possible values are none, warn, reject.
	Enforcement Enforcement `yaml:"enforcement" conf:",example=reject"`
	// CacheSize defines the number of schemas to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",example=1024"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Enforcement = defaultEnforcement
	c.CacheSize = defaultCacheSize
}

// Enforcement level for schema validation.
type Enforcement string

const (
	EnforcementNone   Enforcement = "none"   // No enforcement made.
	EnforcementWarn   Enforcement = "warn"   // In case schema is not validated, display a warning.
	EnforcementReject Enforcement = "reject" // In case schema is not validated, reject.
)

func NewConf(enforcement Enforcement) *Conf {
	c := &Conf{}
	c.SetDefaults()

	c.Enforcement = enforcement
	return c
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
