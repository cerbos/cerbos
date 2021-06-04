// Copyright 2021 Zenauth Ltd.

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
