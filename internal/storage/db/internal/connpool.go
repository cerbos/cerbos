// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"time"

	"github.com/jmoiron/sqlx"
)

// ConnPoolConf holds common SQL connection pool settings.
type ConnPoolConf struct {
	MaxLifetime time.Duration `yaml:"maxLifeTime"`
	MaxIdleTime time.Duration `yaml:"maxIdleTime"`
	MaxOpen     uint          `yaml:"maxOpen"`
	MaxIdle     uint          `yaml:"maxIdle"`
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
