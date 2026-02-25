// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package util

import (
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/nlepage/go-tarfs"
	"google.golang.org/protobuf/proto"
)

// LoadFromJSONOrYAML reads a JSON or YAML encoded protobuf from the given path.
func LoadFromJSONOrYAML(fsys fs.FS, path string, dest proto.Message) error {
	f, err := fsys.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}

	defer f.Close()

	return ReadJSONOrYAML(f, dest)
}

// OpenDirectoryFS attempts to open a directory FS at the given location. It'll initially check if the target file is an archive,
// and if so, will return the appropriate type which implements the fs.FS interface.
func OpenDirectoryFS(path string) (fs.FS, error) {
	// We don't use `switch filepath.Ext(path)` here because it only suffixes from the final `.`, so `.tar.gz` won't be
	// correctly handled
	switch {
	case IsZip(path):
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open zip file: %w", err)
		}
		return ClosableFS{FS: zr, closers: []io.Closer{zr}}, nil
	case IsTar(path):
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open tar file: %w", err)
		}

		return getFsFromTar(f, f)
	case IsGzip(path):
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open gzip file: %w", err)
		}

		gzr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to open gzip file: %w", err)
		}

		return getFsFromTar(gzr, gzr, f)
	}

	return os.DirFS(path), nil
}

func getFsFromTar(r io.Reader, closers ...io.Closer) (fs.FS, error) {
	tfs, err := tarfs.New(r)
	if err != nil {
		for _, c := range closers {
			_ = c.Close()
		}
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}

	return ClosableFS{FS: tfs, closers: closers}, nil
}
