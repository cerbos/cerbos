// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"time"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	confKey                  = storage.ConfKey + ".overlay"
	defaultFailoverThreshold = 5
	defaultFailoverInterval  = 5 * time.Minute
)

// Conf is required (if driver is set to 'overlay') configuration for overlay storage driver.
// +desc=This section is required only if storage.driver is overlay.
type Conf struct {
	// BaseDriver is the default storage driver
	BaseDriver string `yaml:"baseDriver" conf:"required,example=disk"`
	// FallbackDriver is the secondary or fallback storage driver
	FallbackDriver string `yaml:"fallbackDriver" conf:"required,example=git"`
	// FailoverThreshold is the max number of errors we allow within the failoverInterval period
	FailoverThreshold int `yaml:"failoverThreshold,omitempty" conf:",example=5"`
	// FailoverInterval is the cyclic period within which we aggregate failures
	FailoverInterval time.Duration `yaml:"failoverInterval" conf:",example=5m"`
}

func (conf *Conf) Key() string {
	return confKey
}

func (conf *Conf) SetDefaults() {
	if conf.FailoverThreshold == 0 {
		conf.FailoverThreshold = defaultFailoverThreshold
	}
	if conf.FailoverInterval == 0 {
		conf.FailoverInterval = defaultFailoverInterval
	}
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
