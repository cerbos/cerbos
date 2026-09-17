// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
)

const (
	confKey = audit.ConfKey + ".local"

	defaultBufferSize         = 16
	defaultFlushInterval      = 30 * time.Second
	defaultMaxBatchSize       = 16
	defaultGCInterval         = 15 * time.Minute
	defaultBadgerMemTableSize = 32 << 20             //nolint:mnd
	defaultRetentionPeriod    = (7 * 24) * time.Hour //nolint:mnd

	minFlushInterval      = 1 * time.Second
	minBadgerMemTableSize = 1 << 20 //nolint:mnd
	minRetentionPeriod    = 1 * time.Hour
	maxRetentionPeriod    = (30 * 24) * time.Hour //nolint:mnd
)

var (
	errEmptyStoragePath          = errors.New("storagePath should not be empty")
	errInvalidBufferSize         = errors.New("bufferSize must be at least 1")
	errInvalidMaxBatchSize       = errors.New("maxBatchSize must be at least 1")
	errInvalidBadgerMemTableSize = fmt.Errorf("badgerMemTableSize must be at least %d bytes", minBadgerMemTableSize)
)

// Conf is optional configuration for local Audit.
type Conf struct {
	// Path to store the data
	StoragePath string `yaml:"storagePath" conf:",example=/path/to/dir"`
	// How long to keep records for
	RetentionPeriod time.Duration `yaml:"retentionPeriod" conf:",example=168h"`
	Advanced        AdvancedConf  `yaml:"advanced"`
}

type AdvancedConf struct {
	// Size of the Badger memtable in bytes. Do not reduce it on an existing database after an unclean shutdown: the leftover write-ahead log (*.mem) must fit the new size to be replayed, and startup fails if it does not.
	BadgerMemTableSize uint64        `yaml:"badgerMemTableSize" conf:",example=33554432"`
	BufferSize         uint          `yaml:"bufferSize" conf:",example=256"`
	MaxBatchSize       uint          `yaml:"maxBatchSize" conf:",example=32"`
	FlushInterval      time.Duration `yaml:"flushInterval" conf:",example=1s"`
	GCInterval         time.Duration `yaml:"gcInterval" conf:",example=60s"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.RetentionPeriod = defaultRetentionPeriod
	c.Advanced.BadgerMemTableSize = defaultBadgerMemTableSize
	c.Advanced.BufferSize = defaultBufferSize
	c.Advanced.MaxBatchSize = defaultMaxBatchSize
	c.Advanced.FlushInterval = defaultFlushInterval
	c.Advanced.GCInterval = defaultGCInterval
}

func (c *Conf) Validate() error {
	if strings.TrimSpace(c.StoragePath) == "" {
		return errEmptyStoragePath
	}

	if c.RetentionPeriod < minRetentionPeriod || c.RetentionPeriod > maxRetentionPeriod {
		return fmt.Errorf("retentionPeriod must be between %s and %s", minRetentionPeriod, maxRetentionPeriod)
	}

	if c.Advanced.BufferSize < 1 {
		return errInvalidBufferSize
	}

	if c.Advanced.MaxBatchSize < 1 {
		return errInvalidMaxBatchSize
	}

	if c.Advanced.BadgerMemTableSize < minBadgerMemTableSize {
		return errInvalidBadgerMemTableSize
	}

	if c.Advanced.FlushInterval < minFlushInterval {
		return fmt.Errorf("flushInterval must be at least %s", minFlushInterval)
	}

	return nil
}
