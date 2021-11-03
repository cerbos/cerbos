// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../../hack/tools/confdocs.go

package disk

import (
	"github.com/cerbos/cerbos/internal/storage"
)

const confKey = storage.ConfKey + ".disk"

// Conf holds the configuration for disk storage driver.
type Conf struct {
	// Directory is the path on disk where policies are stored.
	Directory string `yaml:"directory" conf:"required"`
	// WatchForChanges enables watching the directory for changes.
	WatchForChanges bool `yaml:"watchForChanges" conf:"required"`
	// [DEPRECATED] ScratchDir is the directory to use for holding temporary data.
	ScratchDir string `yaml:"scratchDir"`
}

func (conf *Conf) Key() string {
	return confKey
}
