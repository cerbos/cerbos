// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run -tags=confdocs ./../../../../hack/tools/confdocs/confdocs.go

package mysql

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".mysql"

// Conf is required (if driver is set to 'mysql') configuration for mysql driver.
type Conf struct {
	// Data source name
	DSN          string                 `yaml:"dsn" conf:"required,defaultValue=\"user:password@tcp(localhost:3306)/db?interpolateParams=true\""`
	ConnPool     *internal.ConnPoolConf `yaml:"connPool" conf:",defaultValue=\n      maxLifeTime: 60m\n      maxIdleTime: 45s\n      maxOpen: 4\n      maxIdle: 1"`
	TLS          map[string]TLSConf     `yaml:"tls" conf:",defaultValue=\n        mytls:\n          cert: /path/to/certificate\n          key: /path/to/private_key\n          caCert: /path/to/CA_certificate"`
	ServerPubKey map[string]string      `yaml:"serverPubKey" conf:",defaultValue=\n        mykey: testdata/server_public_key.pem"`
}

type TLSConf struct {
	CACert string `yaml:"caCert"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

func (c *Conf) Key() string {
	return confKey
}
