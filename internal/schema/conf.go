// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import "path/filepath"

const (
	confKey                     = "schema"
	defaultIgnoreUnknownFields  = true
	defaultEnforcement          = EnforcementNone
	defaultIgnoreSchemaNotFound = false
)

var (
	RelativePathToSchema = filepath.Join("_schemas", "schema.yaml")
)

// Conf holds configuration related to schema validation
type Conf struct {
	// IgnoreUnknownFields Ignores fields not defined in the schema
	IgnoreUnknownFields bool `yaml:"ignoreUnknownFields"`
	// IgnoreSchemaNotFound Ignores schema file not found error
	IgnoreSchemaNotFound bool `yaml:"ignoreSchemaNotFound"`
	// Enforcement level of the validations. (none, warn, reject)
	Enforcement Enforcement `yaml:"enforcement"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.IgnoreUnknownFields = defaultIgnoreUnknownFields
	c.IgnoreSchemaNotFound = defaultIgnoreSchemaNotFound
	c.Enforcement = defaultEnforcement
}

// Enforcement level for schema validation
type Enforcement string

const (
	EnforcementNone   Enforcement = "none"   // No enforcement made.
	EnforcementWarn   Enforcement = "warn"   // In case schema is not validated, display a warning.
	EnforcementReject Enforcement = "reject" // In case schema is not validated, reject.
)
