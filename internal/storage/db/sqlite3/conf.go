// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run -tags=confdocs ./../../../../hack/tools/confdocs/confdocs.go

package sqlite3

import "github.com/cerbos/cerbos/internal/storage"

const confKey = storage.ConfKey + ".sqlite3"

// Conf is required (if driver is set to 'sqlite3') configuration for sqlite3 driver.
type Conf struct {
	// Data source name
	DSN string `yaml:"dsn" conf:"required,defaultValue=\":memory:?_fk=true\""`
}

func (c *Conf) Key() string {
	return confKey
}
