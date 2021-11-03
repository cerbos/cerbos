// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../../../hack/tools/confdocs.go

package mysql

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".mysql"

type Conf struct {
	DSN          string                 `yaml:"dsn"`
	ConnPool     *internal.ConnPoolConf `yaml:"connPool"`
	TLS          map[string]TLSConf     `yaml:"tls"`
	ServerPubKey map[string]string      `yaml:"serverPubKey"`
}

type TLSConf struct {
	CACert string `yaml:"caCert"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

func (c *Conf) Key() string {
	return confKey
}
