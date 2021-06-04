// Copyright 2021 Zenauth Ltd.

package sqlite3

import "github.com/cerbos/cerbos/internal/storage"

const confKey = storage.ConfKey + ".sqlite3"

type Conf struct {
	DSN string `yaml:"dsn"`
}

func (c *Conf) Key() string {
	return confKey
}
