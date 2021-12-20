// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run -tags=confdocs ./../../../../hack/tools/confdocs/confdocs.go

package postgres

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".postgres"

// Conf is required (if driver is set to 'postres') configuration for postres driver.
type Conf struct {
	// URL is the Postgres connection URL. See https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
	URL      string                 `yaml:"url" conf:"required,defaultValue=\"postgres://user:password@localhost:port/db\""`
	ConnPool *internal.ConnPoolConf `yaml:"connPool" conf:",defaultValue=\n      maxLifeTime: 60m\n      maxIdleTime: 45s\n      maxOpen: 4\n      maxIdle: 1"`
}

func (c *Conf) Key() string {
	return confKey
}
