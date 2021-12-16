// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../../hack/tools/confdocs.go

package disk

import (
	"github.com/cerbos/cerbos/internal/storage"
)

const confKey = storage.ConfKey + ".disk"

// Required (if driver is set to 'disk'). Configuration for disk storage driver.
type Conf struct {
	// The path on disk where policies are stored.
	Directory string `yaml:"directory" conf:"required,defaultValue=pkg/test/testdata/store"`
	// Enables watching the directory for changes.
	WatchForChanges bool `yaml:"watchForChanges" conf:"required,defaultValue=false"`
	// [DEPRECATED] ScratchDir is the directory to use for holding temporary data.
	ScratchDir string `yaml:"scratchDir" conf:",ignore"`
}

func (conf *Conf) Key() string {
	return confKey
}
