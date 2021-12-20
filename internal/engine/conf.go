// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../hack/tools/confdocs/confdocs.go

package engine

import (
	"errors"
	"runtime"
	"strings"

	"github.com/cerbos/cerbos/internal/namer"
)

const confKey = "engine"

var errEmptyDefaultVersion = errors.New("engine.defaultVersion must not be an empty string")

// Conf is optional configuration for engine.
type Conf struct {
	// DefaultPolicyVersion defines what version to assume if the request does not specify one.
	DefaultPolicyVersion string `yaml:"defaultPolicyVersion" conf:",defaultValue=\"default\""`
	NumWorkers           uint   `yaml:"numWorkers" conf:",ignore"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.DefaultPolicyVersion = namer.DefaultVersion
	c.NumWorkers = uint(runtime.NumCPU() + 4) //nolint:gomnd
}

func (c *Conf) Validate() error {
	if strings.TrimSpace(c.DefaultPolicyVersion) == "" {
		return errEmptyDefaultVersion
	}

	return nil
}
