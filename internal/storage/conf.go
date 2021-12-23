// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

const (
	defaultDriver = "disk"
	ConfKey       = "storage"
)

// Conf is required configuration for storage.
//+desc=This section is required. The field driver must be set to indicate which driver to use.
type Conf struct {
	// Driver states which storage driver to use. Possible values are blob, mysql, postgres, sqlite3, disk and git.
	Driver string `yaml:"driver" conf:"required,defaultValue=\"disk\""`
}

func (c *Conf) Key() string {
	return ConfKey
}

func (c *Conf) SetDefaults() {
	c.Driver = defaultDriver
}
