// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"fmt"
	"strings"

	"github.com/cerbos/cerbos/internal/audit"
)

const confKey = audit.ConfKey + ".file"

// Conf is optional configuration for file Audit.
type Conf struct {
	// LogRotation settings (optional).
	LogRotation *LogRotationConf `yaml:"logRotation"`
	// Path to the log file to use as output. The special values stdout and stderr can be used to write to stdout or stderr respectively.
	Path string `yaml:"path" conf:"required,example=/path/to/file.log"`
	// AdditionalPaths to mirror the log output. Has performance implications. Use with caution.
	AdditionalPaths []string `yaml:"additionalPaths" conf:",example=[stdout]"`
}

//nolint:tagliatelle
type LogRotationConf struct {
	// MaxFileSizeMB sets the maximum size of individual log files in megabytes.
	MaxFileSizeMB uint `yaml:"maxFileSizeMB" conf:",example=100"`
	// MaxFileAgeDays sets the maximum age in days of old log files before they are deleted.
	MaxFileAgeDays uint `yaml:"maxFileAgeDays" conf:",example=10"`
	// MaxFileCount sets the maximum number of files to retain.
	MaxFileCount uint `yaml:"maxFileCount" conf:",example=10"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Path = "stdout"
}

func (c *Conf) Validate() error {
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("invalid path %q", c.Path)
	}

	return nil
}
