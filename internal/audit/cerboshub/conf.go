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

	defaultMaxBatchSize     = 16
	defaultMinFlushInterval = 5 * time.Second
	defaultFlushTimeout     = 5 * time.Second
	defaultNumGoRoutines    = 8

	minMinFlushInterval = 2 * time.Second
	maxFlushTimeout     = 10 * time.Second
)

var (
	errInvalidFlushInterval = fmt.Errorf("flushInterval must be at least %s", minMinFlushInterval)
	errInvalidFlushTimeout  = fmt.Errorf("flushTimeout cannot be more than %s", maxFlushTimeout)
)

type Conf struct {
	local.Conf
	Ingest IngestConf `yaml:"ingest"`
}

type IngestConf struct {
	MaxBatchSize     uint          `yaml:"maxBatchSize" conf:",example=32"`
	MinFlushInterval time.Duration `yaml:"minFlushInterval" conf:",example=10s"`
	FlushTimeout     time.Duration `yaml:"flushTimeout" conf:",example=5s"`
	NumGoRoutines    uint          `yaml:"numGoRoutines" conf:",example=8"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Conf.SetDefaults()

	c.Ingest.MaxBatchSize = defaultMaxBatchSize
	c.Ingest.MinFlushInterval = defaultMinFlushInterval
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

	if c.Ingest.MinFlushInterval < minMinFlushInterval {
		return errInvalidFlushInterval
	}

	if c.Ingest.FlushTimeout > maxFlushTimeout {
		return errInvalidFlushTimeout
	}

	if c.Ingest.FlushTimeout > c.Ingest.MinFlushInterval {
		return errors.New("flushTimeout cannot be longer than flushInterval")
	}

	if c.Ingest.MinFlushInterval >= c.Advanced.FlushInterval {
		return errors.New("ingest.minFlushInterval must be less than advanced.flushInterval")
	}

	return nil
}
