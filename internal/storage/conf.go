// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

const (
	ConfKey       = "storage"
	driverConfKey = "storage.driver"
)

// Conf is required configuration for storage.
//+desc=This section is required. The field driver must be set to indicate which driver to use.
type Conf struct {
	// Driver states which storage driver to use. Possible values are blob, mysql, postgres, sqlite3, disk and git.
	Driver string `yaml:"driver" conf:"required,example=\"disk\""`
}

func (c *Conf) Key() string {
	return ConfKey
}
