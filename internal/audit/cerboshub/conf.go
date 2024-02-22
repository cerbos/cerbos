// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerboshub

import (
	"time"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
)

const (
	confKey = audit.ConfKey + ".cerboshub"
)

type Conf struct {
	local.Conf
	Ingest IngestConf `yaml:"ingest"`
}

type IngestConf struct {
	BatchSize     uint          `yaml:"batchSize" conf:",example=32"`
	FlushInterval time.Duration `yaml:"flushInterval" conf:",example=10s"`
	NumGoRoutines uint          `yaml:"numGoRoutines" conf:",example=8"`
}

func (c *Conf) Key() string {
	return confKey
}
