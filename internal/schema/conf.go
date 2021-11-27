// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

const (
	confKey                     = "schema"
	defaultEnforcement          = EnforcementNone
	defaultIgnoreSchemaNotFound = false
)

// Conf holds configuration related to schema validation.
type Conf struct {
	// IgnoreSchemaNotFound Ignores schema file not found error
	IgnoreSchemaNotFound bool `yaml:"ignoreSchemaNotFound"`
	// Enforcement level of the validations. (none, warn, reject)
	Enforcement Enforcement `yaml:"enforcement"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.IgnoreSchemaNotFound = defaultIgnoreSchemaNotFound
	c.Enforcement = defaultEnforcement
}

// Enforcement level for schema validation.
type Enforcement string

const (
	EnforcementNone   Enforcement = "none"   // No enforcement made.
	EnforcementWarn   Enforcement = "warn"   // In case schema is not validated, display a warning.
	EnforcementReject Enforcement = "reject" // In case schema is not validated, reject.
)
