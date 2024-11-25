// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlserver

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".sqlserver"

// Conf is required (if driver is set to 'sqlserver') configuration for mssql driver.
// +desc=Deprecated. SQL Server will no longer be supported in future Cerbos releases.
type Conf struct {
	ConnPool  *internal.ConnPoolConf  `yaml:"connPool" conf:",example=\n  maxLifeTime: 60m\n  maxIdleTime: 45s\n  maxOpen: 4\n  maxIdle: 1"`
	ConnRetry *internal.ConnRetryConf `yaml:"connRetry" conf:",example=\n  maxAttempts: 3\n  initialInterval: 0.5s\n  maxInterval: 60s"`
	// URL is the SQL Server connection URL. See https://github.com/microsoft/go-mssqldb#connection-parameters-and-dsn.
	URL string `yaml:"url" conf:"required,example=\"sqlserver://username:password@host/instance?param1=value&param2=value\""`
	// SkipSchemaCheck skips checking for required database tables on startup.
	SkipSchemaCheck bool `yaml:"skipSchemaCheck" conf:",example=false"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) Validate() error {
	return c.ConnRetry.Validate()
}
