// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"time"

	"github.com/jmoiron/sqlx"
)

// ConnPoolConf holds common SQL connection pool settings.
type ConnPoolConf struct {
	MaxLifetime time.Duration `yaml:"maxLifeTime" conf:",defaultValue=60m"`
	MaxIdleTime time.Duration `yaml:"maxIdleTime" conf:",defaultValue=45s"`
	MaxOpen     uint          `yaml:"maxOpen" conf:",defaultValue=4"`
	MaxIdle     uint          `yaml:"maxIdle" conf:",defaultValue=1"`
}

func (cc *ConnPoolConf) Configure(db *sqlx.DB) {
	if cc == nil {
		return
	}

	db.SetConnMaxLifetime(cc.MaxLifetime)
	db.SetConnMaxIdleTime(cc.MaxIdleTime)
	db.SetMaxIdleConns(int(cc.MaxIdle))
	db.SetMaxOpenConns(int(cc.MaxOpen))
}
