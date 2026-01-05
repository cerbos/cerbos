// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package sqlite3

import "github.com/cerbos/cerbos/internal/storage"

const confKey = storage.ConfKey + ".sqlite3"

// Conf is required (if driver is set to 'sqlite3') configuration for sqlite3 driver.
// +desc=This section is required only if storage.driver is sqlite3.
type Conf struct {
	// Data source name
	DSN string `yaml:"dsn" conf:"required,example=\":memory:?_fk=true\""`
}

func (c *Conf) Key() string {
	return confKey
}
