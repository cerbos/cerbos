// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package mysql

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".mysql"

// Conf is required (if driver is set to 'mysql') configuration for mysql driver.
//+desc=This section is required only if storage.driver is mysql.
type Conf struct {
	ConnPool     *internal.ConnPoolConf `yaml:"connPool" conf:",example=\n  maxLifeTime: 60m\n  maxIdleTime: 45s\n  maxOpen: 4\n  maxIdle: 1"`
	TLS          map[string]TLSConf     `yaml:"tls" conf:",example=\n  mytls:\n    cert: /path/to/certificate\n    key: /path/to/private_key\n    caCert: /path/to/CA_certificate"`
	ServerPubKey map[string]string      `yaml:"serverPubKey" conf:",example=\n  mykey: testdata/server_public_key.pem"`
	// DSN is the data source connection string.
	DSN string `yaml:"dsn" conf:"required,example=\"user:password@tcp(localhost:3306)/db?interpolateParams=true\""`
}

type TLSConf struct {
	CACert string `yaml:"caCert"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

func (c *Conf) Key() string {
	return confKey
}
