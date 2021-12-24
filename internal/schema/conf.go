// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

const (
	confKey            = "schema"
	defaultEnforcement = EnforcementNone
)

// Conf is optional configuration for schema validation.
type Conf struct {
	// Enforcement defines level of the validations. Possible values are none, warn, reject.
	Enforcement Enforcement `yaml:"enforcement" conf:",example=reject"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Enforcement = defaultEnforcement
}

// Enforcement level for schema validation.
type Enforcement string

const (
	EnforcementNone   Enforcement = "none"   // No enforcement made.
	EnforcementWarn   Enforcement = "warn"   // In case schema is not validated, display a warning.
	EnforcementReject Enforcement = "reject" // In case schema is not validated, reject.
)
