// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

const Directory = "_schemas"

type FSLoader struct {
	err      error
	compiler *jsonschema.Compiler
}

func NewFSLoader(fsys fs.FS, rootDir string) *FSLoader {
	schemaDir := filepath.Join(rootDir, Directory)
	schemaFS, err := fs.Sub(fsys, schemaDir)
	if err != nil {
		return &FSLoader{err: err}
	}

	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true
	compiler.LoadURL = func(path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		if u.Scheme == URLScheme {
			relativePath := strings.TrimPrefix(u.Path, "/")
			return schemaFS.Open(relativePath)
		}

		loader, ok := jsonschema.Loaders[u.Scheme]
		if !ok {
			return nil, jsonschema.LoaderNotFoundError(path)
		}
		return loader(path)
	}

	return &FSLoader{compiler: compiler}
}

func (sl *FSLoader) Load(_ context.Context, url string) (*jsonschema.Schema, error) {
	if sl.err != nil {
		return nil, sl.err
	}

	return sl.compiler.Compile(url)
}
