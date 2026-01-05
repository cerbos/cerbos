// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"fmt"
	"io"
	"io/fs"
)

type Found interface {
	Open() (io.Reader, error)
	ID() string
	Path() string
}

type foundInFs struct {
	fsys fs.FS
	id   string
	path string
}

func (f foundInFs) Open() (io.Reader, error) {
	file, err := f.fsys.Open(f.path)
	if err != nil {
		return nil, fmt.Errorf("failed to open found file from %s: %w", f.path, err)
	}

	return file, nil
}

func (f foundInFs) ID() string {
	return f.id
}

func (f foundInFs) Path() string {
	return f.path
}
