// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../hack/tools/confdocs.go

package schema

const (
	confKey            = "schema"
	defaultEnforcement = EnforcementNone
)

// Conf holds configuration related to schema validation.
type Conf struct {
	// Enforcement level of the validations. (none, warn, reject)
	Enforcement Enforcement `yaml:"enforcement" conf:",defaultValue=reject"`
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
