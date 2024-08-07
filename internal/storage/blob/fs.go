// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

var _ clonerFS = storeFS{}

type storeFS struct {
	dir string
}

func (s storeFS) Open(name string) (fs.File, error) {
	return os.Open(filepath.Join(s.dir, name))
}

func (s storeFS) Remove(name string) error {
	return os.Remove(filepath.Join(s.dir, name))
}

func (s storeFS) Create(name string) (io.WriteCloser, error) {
	return os.Create(filepath.Join(s.dir, name))
}

func (s storeFS) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(filepath.Join(s.dir, path), perm)
}
