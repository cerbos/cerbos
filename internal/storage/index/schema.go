// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/cerbos/cerbos/internal/schema"
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

func (sl *SchemaLoader) Load(_ context.Context, id string) (io.ReadCloser, error) {
	if sl.err != nil {
		return nil, sl.err
	}

	return sl.fsys.Open(id)
}
