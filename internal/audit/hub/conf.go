// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"errors"
	"fmt"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"go.uber.org/multierr"
)

const (
	confKey = audit.ConfKey + ".hub"

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
	// Mask defines a list of attributes to exclude from the audit logs, specified as lists of JSONPaths
	Mask       MaskConf `yaml:"mask"`
	local.Conf `yaml:",inline"`
	Ingest     IngestConf `yaml:"ingest" conf:",ignore"`
}

type IngestConf struct {
	// MaxBatchSize defines the max number of log entries to send in each Ingest request.
	MaxBatchSize uint `yaml:"maxBatchSize" conf:",example=32"`
	// MinFlushInterval is the minimal duration between Ingest requests.
	MinFlushInterval time.Duration `yaml:"minFlushInterval" conf:",example=3s"`
	// FlushTimeout defines the max allowable timeout for each Ingest request.
	FlushTimeout time.Duration `yaml:"flushTimeout" conf:",example=5s"`
	// NumGoRoutines defines the max number of goroutines used when streaming log entries from the local DB.
	NumGoRoutines uint `yaml:"numGoRoutines" conf:",example=8"`
}

type MaskConf struct {
	Peer           []string `yaml:"peer" conf:",example=\n    - address\n    - forwarded_for"`
	Metadata       []string `yaml:"metadata" conf:",example=['authorization']"`
	CheckResources []string `yaml:"checkResources" conf:",example=\n    - inputs[*].principal.attr.foo\n    - inputs[*].auxData\n    - outputs"`
	PlanResources  []string `yaml:"planResources" conf:",example=['input.principal.attr.nestedMap.foo']"`
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

func (c *Conf) Validate() (outErr error) {
	if err := c.Conf.Validate(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	if c.Ingest.MaxBatchSize < 1 {
		outErr = multierr.Append(outErr, errors.New("maxBatchSize must be at least 1"))
	}

	if c.Ingest.MinFlushInterval < minMinFlushInterval {
		outErr = multierr.Append(outErr, errInvalidFlushInterval)
	}

	if c.Ingest.FlushTimeout > maxFlushTimeout {
		outErr = multierr.Append(outErr, errInvalidFlushTimeout)
	}

	if c.Ingest.MinFlushInterval >= c.Conf.Advanced.FlushInterval {
		outErr = multierr.Append(outErr, errors.New("ingest.minFlushInterval must be less than advanced.flushInterval"))
	}

	return outErr
}
