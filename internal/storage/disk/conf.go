// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
)

const confKey = storage.ConfKey + ".disk"

// Conf is required (if driver is set to 'disk') configuration for disk storage driver.
// +desc=This section is required only if storage.driver is disk.
type Conf struct {
	// Directory is the path on disk where policies are stored.
	Directory string `yaml:"directory" conf:"required,example=pkg/test/testdata/store"`
	// [DEPRECATED] ScratchDir is the directory to use for holding temporary data.
	ScratchDir string `yaml:"scratchDir" conf:",ignore"`
	// WatchForChanges enables watching the directory for changes.
	WatchForChanges bool `yaml:"watchForChanges" conf:"required,example=false"`
}

func (conf *Conf) Key() string {
	return confKey
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
