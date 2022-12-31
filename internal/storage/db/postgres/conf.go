// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".postgres"

// Conf is required (if driver is set to 'postres') configuration for postres driver.
// +desc=This section is required only if storage.driver is postgres.
type Conf struct {
	ConnPool *internal.ConnPoolConf `yaml:"connPool" conf:",example=\n  maxLifeTime: 60m\n  maxIdleTime: 45s\n  maxOpen: 4\n  maxIdle: 1"`
	// URL is the Postgres connection URL. See https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
	URL string `yaml:"url" conf:"required,example=\"postgres://user:password@localhost:port/db\""`
}

func (c *Conf) Key() string {
	return confKey
}
