// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlserver

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".sqlserver"

// Conf is required (if driver is set to 'sqlserver') configuration for mssql driver.
// +desc=This section is required only if storage.driver is sqlserver.
type Conf struct {
	ConnPool *internal.ConnPoolConf `yaml:"connPool" conf:",example=\n  maxLifeTime: 60m\n  maxIdleTime: 45s\n  maxOpen: 4\n  maxIdle: 1"`
	// URL is the SQL Server connection URL. See https://github.com/denisenkom/go-mssqldb#connection-parameters-and-dsn
	URL string `yaml:"url" conf:"required,example=\"sqlserver://username:password@host/instance?param1=value&param2=value\""`
}

func (c *Conf) Key() string {
	return confKey
}
