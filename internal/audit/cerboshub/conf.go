// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerboshub

import (
	"errors"
	"fmt"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/hub"
	"go.uber.org/multierr"
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
	Ingest IngestConf `yaml:"ingest"`
	// Local is configuration for the local Audit backend. See 'audit.local' section for documentation
	Local local.Conf `yaml:"local" conf:",example=see audit.local section"`
}

type IngestConf struct {
	// Credentials holds bundle source credentials.
	Credentials *hub.CredentialsConf `yaml:"credentials" conf:",ignore"`
	// Connection defines settings for the remote server connection.
	Connection *hub.ConnectionConf `yaml:"connection" conf:",ignore"`
	// MaxBatchSize defines the max number of log entries to send in each Ingest request.
	MaxBatchSize uint `yaml:"maxBatchSize" conf:",example=32"`
	// MinFlushInterval is the minimal duration between Ingest requests.
	MinFlushInterval time.Duration `yaml:"minFlushInterval" conf:",example=10s"`
	// FlushTimeout defines the max allowable timeout for each Ingest request.
	FlushTimeout time.Duration `yaml:"flushTimeout" conf:",example=5s"`
	// NumGoRoutines defines the max number of goroutines used when streaming log entries from the local DB.
	NumGoRoutines uint `yaml:"numGoRoutines" conf:",example=8"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Local.SetDefaults()

	c.Ingest.MaxBatchSize = defaultMaxBatchSize
	c.Ingest.MinFlushInterval = defaultMinFlushInterval
	c.Ingest.FlushTimeout = defaultFlushTimeout
	c.Ingest.NumGoRoutines = defaultNumGoRoutines
}

func (c *Conf) Validate() (outErr error) {
	if err := c.Local.Validate(); err != nil {
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

	// TODO(saml) is this a stupid rule?
	// if c.Ingest.FlushTimeout > c.Ingest.MinFlushInterval {
	// 	outErr = multierr.Append(outErr, errors.New("ingest.flushTimeout cannot be longer than ingest.minFlushInterval"))
	// }

	if c.Ingest.MinFlushInterval >= c.Local.Advanced.FlushInterval {
		outErr = multierr.Append(outErr, errors.New("ingest.minFlushInterval must be less than advanced.flushInterval"))
	}

	if err := c.loadHubConf(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	return outErr
}

func (c *Conf) loadHubConf() (outErr error) {
	hubConf, err := hub.GetConf()
	if err != nil {
		outErr = multierr.Append(outErr, fmt.Errorf("failed to read Cerbos Hub configuration: %w", err))
	}

	c.Ingest.Connection = &hubConf.Connection
	if err := c.Ingest.Connection.Validate(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	c.Ingest.Credentials = &hubConf.Credentials
	if err := c.Ingest.Credentials.Validate(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	return outErr
}
