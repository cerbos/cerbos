// Copyright 2021-2025 Zenauth Ltd.
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

	defaultMinFlushInterval  = 5 * time.Second
	defaultFlushTimeout      = 5 * time.Second
	defaultNumGoRoutines     = 4
	defaultMaxBatchSizeBytes = 4194304 // 4MB

	minMinFlushInterval = 2 * time.Second
	maxFlushTimeout     = 10 * time.Second
	// Arbitrary figure to account for additional metadata in the batch message as we only track the size of each entry at write time.
	// It's not the end of the world if the batch size exceeds the limit (due to this number being set too low), but
	// it reduces the chance of that happening.
	BatchSizeToleranceBytes = 128
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
	// MaxBatchSizeBytes defines the max cumulative size in bytes for a batch of log entries.
	MaxBatchSizeBytes uint `yaml:"maxBatchSizeBytes" conf:",example=2097152,ignore"`
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

	c.Ingest.MaxBatchSizeBytes = defaultMaxBatchSizeBytes
	c.Ingest.MinFlushInterval = defaultMinFlushInterval
	c.Ingest.FlushTimeout = defaultFlushTimeout
	c.Ingest.NumGoRoutines = defaultNumGoRoutines
}

func (c *Conf) Validate() (outErr error) {
	if err := c.Conf.Validate(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	if c.Ingest.MaxBatchSizeBytes < BatchSizeToleranceBytes {
		outErr = multierr.Append(outErr, fmt.Errorf("maxBatchSizeBytes must be at least %d", BatchSizeToleranceBytes))
	}

	if c.Ingest.MaxBatchSizeBytes > local.MaxAllowedBatchSizeBytes-BatchSizeToleranceBytes {
		outErr = multierr.Append(outErr, fmt.Errorf("maxBatchSizeBytes cannot exceed %d bytes", local.MaxAllowedBatchSizeBytes-BatchSizeToleranceBytes))
	}

	if c.Ingest.MinFlushInterval < minMinFlushInterval {
		outErr = multierr.Append(outErr, errInvalidFlushInterval)
	}

	if c.Ingest.FlushTimeout > maxFlushTimeout {
		outErr = multierr.Append(outErr, errInvalidFlushTimeout)
	}

	if c.Ingest.MinFlushInterval >= c.Advanced.FlushInterval {
		outErr = multierr.Append(outErr, errors.New("ingest.minFlushInterval must be less than advanced.flushInterval"))
	}

	return outErr
}
