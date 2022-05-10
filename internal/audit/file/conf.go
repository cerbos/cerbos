// Copyright 2021-2022 Zenauth Ltd.
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
	// Path to the log file to use as output. The special values stdout and stderr can be used to write to stdout or stderr respectively.
	Path string `yaml:"path" conf:",example=/path/to/file.log"`
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
