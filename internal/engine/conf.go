// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"runtime"
	"strings"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
)

const confKey = "engine"

var errEmptyDefaultVersion = errors.New("engine.defaultVersion must not be an empty string")

// Conf is optional configuration for engine.
type Conf struct {
	// Globals are environment-specific variables to be made available to policy conditions.
	Globals map[string]any `yaml:"globals" conf:",example={\"environment\": \"staging\"}"`
	// DefaultPolicyVersion defines what version to assume if the request does not specify one.
	DefaultPolicyVersion string `yaml:"defaultPolicyVersion" conf:",example=\"default\""`
	// LenientScopeSearch configures the engine to ignore missing scopes and search upwards through the scope tree until it finds a usable policy.
	LenientScopeSearch bool `yaml:"lenientScopeSearch" conf:",example=false"`
	NumWorkers         uint `yaml:"numWorkers" conf:",ignore"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.DefaultPolicyVersion = namer.DefaultVersion
	c.NumWorkers = uint(runtime.NumCPU() + 4) //nolint:mnd
}

func (c *Conf) Validate() error {
	if strings.TrimSpace(c.DefaultPolicyVersion) == "" {
		return errEmptyDefaultVersion
	}

	return nil
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
