// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package overlay

import (
	"errors"
	"time"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
	"go.uber.org/multierr"
)

const (
	confKey                       = storage.ConfKey + ".overlay"
	defaultFallbackErrorThreshold = 5
	defaultFallbackErrorWindow    = 5 * time.Minute
)

// Conf is required (if driver is set to 'overlay') configuration for overlay storage driver.
// +desc=This section is required only if storage.driver is overlay.
type Conf struct {
	// BaseDriver is the default storage driver
	BaseDriver string `yaml:"baseDriver" conf:"required,example=blob"`
	// FallbackDriver is the secondary or fallback storage driver
	FallbackDriver string `yaml:"fallbackDriver" conf:"required,example=disk"`
	// FallbackErrorThreshold is the max number of errors we allow within the fallbackErrorWindow period
	FallbackErrorThreshold int `yaml:"fallbackErrorThreshold,omitempty" conf:",example=5"`
	// FallbackErrorWindow is the cyclic period within which we aggregate failures
	FallbackErrorWindow time.Duration `yaml:"fallbackErrorWindow" conf:",example=5m"`
}

func (conf *Conf) Key() string {
	return confKey
}

func (conf *Conf) Validate() error {
	var errs []error

	if conf.BaseDriver == "" {
		errs = append(errs, errors.New("baseDriver is required"))
	}

	if conf.FallbackDriver == "" {
		errs = append(errs, errors.New("fallbackDriver is required"))
	}

	if conf.BaseDriver != "" && conf.BaseDriver == conf.FallbackDriver {
		errs = append(errs, errors.New("baseDriver and fallbackDriver cannot be the same"))
	}

	if len(errs) > 0 {
		return multierr.Combine(errs...)
	}

	return nil
}

func (conf *Conf) SetDefaults() {
	if conf.FallbackErrorThreshold == 0 {
		conf.FallbackErrorThreshold = defaultFallbackErrorThreshold
	}
	if conf.FallbackErrorWindow == 0 {
		conf.FallbackErrorWindow = defaultFallbackErrorWindow
	}
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
