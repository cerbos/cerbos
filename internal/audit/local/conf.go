// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../gen/gendocsfromconf.go

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
	defaultRetentionPeriod = (7 * 24) * time.Hour //nolint:gomnd

	minFlushInterval   = 5 * time.Second
	minRetentionPeriod = 1 * time.Hour
	maxRetentionPeriod = (30 * 24) * time.Hour //nolint:gomnd
)

var (
	errEmptyStoragePath    = errors.New("storagePath should not be empty")
	errInvalidBufferSize   = errors.New("bufferSize must be at least 1")
	errInvalidMaxBatchSize = errors.New("maxBatchSize must be at least 1")
)

type Conf struct {
	StoragePath     string        `yaml:"storagePath" conf:"optional"`
	RetentionPeriod time.Duration `yaml:"retentionPeriod" conf:"optional"`
	Advanced        AdvancedConf  `yaml:"advanced" conf:"optional"`
}

type AdvancedConf struct {
	BufferSize    uint          `yaml:"bufferSize"`
	MaxBatchSize  uint          `yaml:"maxBatchSize"`
	FlushInterval time.Duration `yaml:"flushInterval"`
	GCInterval    time.Duration `yaml:"gcInterval"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.RetentionPeriod = defaultRetentionPeriod
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

	if c.Advanced.FlushInterval < minFlushInterval {
		return fmt.Errorf("flushInterval must be at least %s", minFlushInterval)
	}

	return nil
}
