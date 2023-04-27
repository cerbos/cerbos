// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
)

const confKey = storage.ConfKey + ".overlay"

// Conf is required (if driver is set to 'overlay') configuration for overlay storage driver.
// +desc=This section is required only if storage.driver is overlay.
type Conf struct {
	// BaseDriver is the secondary or fallback storage driver
	BaseDriver string `yaml:"baseDriver" conf:"required"`
	// FallbackDriver is the primary storage driver
	FallbackDriver string `yaml:"fallbackDriver" conf:"required"`
	// FailoverThreshold is the number of store connection errors seen in the last five minutes.
	FailoverThreshold int `yaml:"failoverThreshold"`
}

func (conf *Conf) Key() string {
	return confKey
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
