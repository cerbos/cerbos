// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package blob

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	perm775 = 0o775
)

var _ FS = blobFS{}

// FS represents file system interface that used by the Cloner and Store.
type FS interface {
	fs.StatFS
	Remove(name string) error
	RemoveAll(name string) error
	Create(name string) (io.WriteCloser, error)
	MkdirAll(path string, perm fs.FileMode) error
}

func newBlobFS(dir string) FS {
	return &blobFS{
		dir:  dir,
		fsys: os.DirFS(dir),
	}
}

type blobFS struct {
	fsys fs.FS
	dir  string
}

func (s blobFS) Create(name string) (io.WriteCloser, error) {
	return os.Create(filepath.Join(s.dir, name))
}

func (s blobFS) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(filepath.Join(s.dir, path), perm)
}

func (s blobFS) Open(name string) (fs.File, error) {
	return s.fsys.Open(name)
}

func (s blobFS) Remove(name string) error {
	return os.Remove(filepath.Join(s.dir, name))
}

func (s blobFS) RemoveAll(name string) error {
	return os.RemoveAll(filepath.Join(s.dir, name))
}

func (s blobFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(s.fsys, name)
}

func createOrValidateDir(dir string) error {
	fileInfo, err := os.Stat(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to stat directory %s: %w", dir, err)
		}

		if err := os.MkdirAll(dir, 0o775); err != nil { //nolint:mnd
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if fileInfo != nil && !fileInfo.IsDir() {
		return fmt.Errorf("dir is not a directory: %s", dir)
	}

	return nil
}
