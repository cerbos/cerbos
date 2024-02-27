// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerboshub

import (
	"errors"
	"fmt"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
)

const (
	confKey = audit.ConfKey + ".cerboshub"

	defaultMaxBatchSize  = 16
	defaultFlushInterval = 30 * time.Second
	defaultFlushTimeout  = 3 * time.Second
	defaultNumGoRoutines = 8

	minFlushInterval = 1 * time.Second
	maxFlushTimeout  = 10 * time.Second
)

var (
	errInvalidFlushInterval = fmt.Errorf("flushInterval must be at least %s", minFlushInterval)
)

type Conf struct {
	local.Conf
	Ingest IngestConf `yaml:"ingest"`
}

type IngestConf struct {
	MaxBatchSize  uint          `yaml:"maxBatchSize" conf:",example=32"`
	FlushInterval time.Duration `yaml:"flushInterval" conf:",example=10s"`
	FlushTimeout  time.Duration `yaml:"flushTimeout" conf:",example=5s"`
	NumGoRoutines uint          `yaml:"numGoRoutines" conf:",example=8"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Conf.SetDefaults()

	c.Ingest.MaxBatchSize = defaultMaxBatchSize
	c.Ingest.FlushInterval = defaultFlushInterval
	c.Ingest.FlushTimeout = defaultFlushTimeout
	c.Ingest.NumGoRoutines = defaultNumGoRoutines
}

func (c *Conf) Validate() error {
	if err := c.Conf.Validate(); err != nil {
		return err
	}

	if c.Ingest.MaxBatchSize < 1 {
		return errors.New("maxBatchSize must be at least 1")
	}

	if c.Ingest.FlushInterval < minFlushInterval {
		return errInvalidFlushInterval
	}

	if c.Ingest.FlushTimeout > c.Ingest.FlushInterval {
		return errors.New("flushTimeout cannot be longer than flushInterval")
	}

	return nil
}
