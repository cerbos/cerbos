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

	defaultBufferSize      = 16
	defaultFlushInterval   = 30 * time.Second
	defaultMaxBatchSize    = 16
	defaultGCInterval      = 15 * time.Minute
	defaulMemtableSize     = 32 << 20             //nolint:mnd
	defaultRetentionPeriod = (7 * 24) * time.Hour //nolint:mnd

	minFlushInterval   = 1 * time.Second
	minMemtableSize    = 1 << 20 //nolint:mnd
	minRetentionPeriod = 1 * time.Hour
	maxRetentionPeriod = (30 * 24) * time.Hour //nolint:mnd
)

var (
	errEmptyStoragePath    = errors.New("storagePath should not be empty")
	errInvalidBufferSize   = errors.New("bufferSize must be at least 1")
	errInvalidMaxBatchSize = errors.New("maxBatchSize must be at least 1")
	errInvalidMemtableSize = fmt.Errorf("memtableSize must be at least %d bytes", minMemtableSize)
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
	// Size of the persistent storage (BadgerDB) memtable in bytes. Larger memtables buffer more writes in memory before flushing to disk, at the cost of a higher memory footprint and a larger write-ahead log (WAL) file. Do not reduce this value if the PDP was shutdown uncleanly and there are leftover WAL files (*.mem) on disk. The PDP will fail to start if the new memtable size is smaller than the leftover WAL file.
	MemtableSize  uint64        `yaml:"memtableSize" conf:",example=33554432"`
	BufferSize    uint          `yaml:"bufferSize" conf:",example=256"`
	MaxBatchSize  uint          `yaml:"maxBatchSize" conf:",example=32"`
	FlushInterval time.Duration `yaml:"flushInterval" conf:",example=1s"`
	GCInterval    time.Duration `yaml:"gcInterval" conf:",example=60s"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.RetentionPeriod = defaultRetentionPeriod
	c.Advanced.MemtableSize = defaulMemtableSize
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

	if c.Advanced.MemtableSize < minMemtableSize {
		return errInvalidMemtableSize
	}

	if c.Advanced.FlushInterval < minFlushInterval {
		return fmt.Errorf("flushInterval must be at least %s", minFlushInterval)
	}

	return nil
}
