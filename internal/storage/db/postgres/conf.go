// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../../../hack/tools/confdocs.go

package postgres

import (
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const confKey = storage.ConfKey + ".postgres"

type Conf struct {
	// URL is the Postgres connection URL. See https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
	URL      string                 `yaml:"url"`
	ConnPool *internal.ConnPoolConf `yaml:"connPool"`
}

func (c *Conf) Key() string {
	return confKey
}
