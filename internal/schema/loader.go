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
	err  error
	fsys fs.FS
}

func NewFSLoader(fsys fs.FS, rootDir string) *FSLoader {
	schemaDir := filepath.Join(rootDir, Directory)
	schemaFS, err := fs.Sub(fsys, schemaDir)
	if err != nil {
		return &FSLoader{err: err}
	}

	return &FSLoader{fsys: schemaFS}
}

func (sl *FSLoader) Load(_ context.Context, url string) (s *jsonschema.Schema, err error) {
	if sl.err != nil {
		return nil, sl.err
	}

	compiler := sl.mkCompiler()
	return compiler.Compile(url)
}

func (sl *FSLoader) mkCompiler() *jsonschema.Compiler {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true
	compiler.LoadURL = func(path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		if u.Scheme == "" || u.Scheme == URLScheme {
			relativePath := strings.TrimPrefix(u.Path, "/")
			return sl.fsys.Open(relativePath)
		}

		loader, ok := jsonschema.Loaders[u.Scheme]
		if !ok {
			return nil, jsonschema.LoaderNotFoundError(path)
		}
		return loader(path)
	}

	return compiler
}
