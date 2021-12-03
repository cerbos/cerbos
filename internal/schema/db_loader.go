// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"io"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type DBLoader struct {
	loadURLFn LoadURLFn
}
type LoadURLFn func(schemaUrl string) (io.ReadCloser, error)

func NewDBLoader(loadURLFn LoadURLFn) *DBLoader {
	return &DBLoader{loadURLFn: loadURLFn}
}

func (dbl *DBLoader) Load(_ context.Context, url string) (*jsonschema.Schema, error) {
	compiler := dbl.mkCompiler()
	return compiler.Compile(url)
}

func (dbl *DBLoader) mkCompiler() *jsonschema.Compiler {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true
	compiler.LoadURL = dbl.loadURLFn

	return compiler
}
