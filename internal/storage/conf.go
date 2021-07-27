// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

const ConfKey = "storage"

// Conf holds storage configuration.
type Conf struct {
	// Driver is the storage driver to use.
	Driver string `yaml:"driver"`
}

func (c *Conf) Key() string {
	return ConfKey
}
