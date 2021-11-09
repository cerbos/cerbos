// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"fmt"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/util"
	"io"
	"io/fs"
)

func ReadSchemaFromFile(fsys fs.FS, path string) (*schemav1.Schema, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}

	defer f.Close()

	return ReadSchema(f)
}

// ReadSchema reads a schema from the given reader.
func ReadSchema(src io.Reader) (*schemav1.Schema, error) {
	schema := &schemav1.Schema{}
	if err := util.ReadJSONOrYAML(src, schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// WriteSchema writes a schema as YAML to the destination.
func WriteSchema(dest io.Writer, p *schemav1.Schema) error {
	return util.WriteYAML(dest, p)
}

// WriteBinarySchema writes a schema as binary (protobuf encoding).
func WriteBinarySchema(dest io.Writer, p *schemav1.Schema) error {
	out, err := p.MarshalVT()
	if err != nil {
		return err
	}

	var buf [128]byte
	_, err = io.CopyBuffer(dest, bytes.NewBuffer(out), buf[:])
	return err
}

// ReadBinarySchema reads a schema from binary (protobuf encoding).
func ReadBinarySchema(src io.Reader) (*schemav1.Schema, error) {
	in, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	p := &schemav1.Schema{}
	if err := p.UnmarshalVT(in); err != nil {
		return nil, err
	}

	return p, nil
}
