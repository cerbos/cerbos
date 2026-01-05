// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"
	"io"
	"io/fs"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
)

func ReadSchemaFromFile(fsys fs.FS, path string) (*schemav1.Schema, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}

	defer f.Close()
	return ReadSchema(f, path)
}

// ReadSchema reads a schema from the given reader.
func ReadSchema(src io.Reader, id string) (*schemav1.Schema, error) {
	def, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read all bytes from reader: %w", err)
	}

	return &schemav1.Schema{
		Id:         id,
		Definition: def,
	}, nil
}
