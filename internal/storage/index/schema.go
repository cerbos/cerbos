// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

type SchemaLoader struct {
	err  error
	fsys fs.FS
}

func NewSchemaLoader(fsys fs.FS, rootDir string) *SchemaLoader {
	schemaDir := filepath.Join(rootDir, schema.Directory)
	schemaFS, err := fs.Sub(fsys, schemaDir)
	if err != nil {
		return &SchemaLoader{err: err}
	}

	return &SchemaLoader{fsys: schemaFS}
}

func (sl *SchemaLoader) ListIDs(_ context.Context) ([]string, error) {
	var schemaIDs []string
	err := fs.WalkDir(sl.fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fs.SkipDir
			}
			return err
		}

		if d.IsDir() {
			if util.IsHidden(d.Name()) {
				return fs.SkipDir
			}

			return nil
		}

		if !util.IsHidden(d.Name()) && util.IsJSONFileTypeExt(d.Name()) {
			schemaIDs = append(schemaIDs, path)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk schemas directory: %w", err)
	}

	return schemaIDs, nil
}

func (sl *SchemaLoader) Load(_ context.Context, id string) (io.ReadCloser, error) {
	if sl.err != nil {
		return nil, sl.err
	}

	return sl.fsys.Open(id)
}
