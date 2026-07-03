// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"go.uber.org/multierr"
)

const (
	confKey = "engine"

	defaultPolicyLoaderTimeout = 2 * time.Second
	extraWorkersOverCPUs       = 4
)

var errEmptyDefaultVersion = errors.New("engine.defaultVersion must not be an empty string")

type CELErrorLogLevel string

const (
	CELErrorLogLevelNone  CELErrorLogLevel = "none"
	CELErrorLogLevelDebug CELErrorLogLevel = "debug"
	CELErrorLogLevelInfo  CELErrorLogLevel = "info"
	CELErrorLogLevelWarn  CELErrorLogLevel = "warn"
	CELErrorLogLevelError CELErrorLogLevel = "error"
)

// Conf is optional configuration for engine.
type Conf struct {
	// Globals are environment-specific variables to be made available to policy conditions.
	Globals map[string]any `yaml:"globals" conf:",example={\"environment\": \"staging\"}"`
	// DefaultPolicyVersion defines what version to assume if the request does not specify one.
	DefaultPolicyVersion string `yaml:"defaultPolicyVersion" conf:",example=\"default\""`
	// DefaultScope defines what scope to assume if the request does not specify one.
	DefaultScope string `yaml:"defaultScope" conf:",example=\"\""`
	// CELErrorLogLevel is the level at which CEL runtime errors raised during policy evaluation are logged. Valid values are none, debug, info, warn (default) and error.
	CELErrorLogLevel CELErrorLogLevel `yaml:"celErrorLogLevel" conf:",example=warn"`
	// LenientScopeSearch configures the engine to ignore missing scopes and search upwards through the scope tree until it finds a usable policy.
	LenientScopeSearch bool `yaml:"lenientScopeSearch" conf:",example=false"`
	// PolicyLoaderTimeout is the timeout for loading policies from the policy store.
	PolicyLoaderTimeout time.Duration `yaml:"policyLoaderTimeout" conf:",example=2s"`
	NumWorkers          uint          `yaml:"numWorkers" conf:",ignore"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.DefaultPolicyVersion = namer.DefaultVersion
	c.DefaultScope = namer.DefaultScope
	c.CELErrorLogLevel = CELErrorLogLevelWarn
	c.PolicyLoaderTimeout = defaultPolicyLoaderTimeout
	c.NumWorkers = uint(runtime.NumCPU() + extraWorkersOverCPUs)
}

func (c *Conf) Validate() (outErr error) {
	if strings.TrimSpace(c.DefaultPolicyVersion) == "" {
		multierr.AppendInto(&outErr, errEmptyDefaultVersion)
	}

	for identifier := range c.Globals {
		if err := conditions.ValidateIdentifier(identifier); err != nil {
			multierr.AppendInto(&outErr, fmt.Errorf("engine.globals: %w", err))
		}
	}

	switch c.CELErrorLogLevel {
	case CELErrorLogLevelNone, CELErrorLogLevelDebug, CELErrorLogLevelInfo, CELErrorLogLevelWarn, CELErrorLogLevelError:
	default:
		multierr.AppendInto(&outErr, fmt.Errorf("engine.celErrorLogLevel: invalid value %q", c.CELErrorLogLevel))
	}

	return outErr
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
