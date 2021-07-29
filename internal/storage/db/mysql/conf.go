// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package mysql

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".mysql"

type Conf struct {
	DSN          string                      `yaml:"dsn"`
	ConnPool     *internal.ConnPoolConf      `yaml:"connPool"`
	TLS          map[string]TLSConf          `yaml:"tls"`
	ServerPubKey map[string]ServerPubKeyConf `yaml:"serverPubKey"`
}

type TLSConf struct {
	CACert string `yaml:"caCert"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

type ServerPubKeyConf struct {
	PubKey string `yaml:"pubKey"`
}

func (c *Conf) Key() string {
	return confKey
}
