// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import "path/filepath"

const (
	confKey                  = "schema"
	defaultIgnoreExtraFields = true
	defaultEnforcement       = EnforcementNone
)

var (
	RelativePathToSchema = filepath.Join("_schemas", "schema.yaml")
)

// Conf holds configuration related to schema validation
type Conf struct {
	// IgnoreExtraFields allows extra fields to be accepted.
	IgnoreExtraFields bool `yaml:"ignoreExtraFields"`
	// Enforcement level of the validations. (none, warn, reject)
	Enforcement Enforcement `yaml:"enforcement"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.IgnoreExtraFields = defaultIgnoreExtraFields
	c.Enforcement = defaultEnforcement
}

// Enforcement level for schema validation
type Enforcement string

const (
	EnforcementNone   Enforcement = "none"   // No enforcement made.
	EnforcementWarn   Enforcement = "warn"   // In case schema is not validated, display a warning.
	EnforcementReject Enforcement = "reject" // In case schema is not validated, reject.
)
