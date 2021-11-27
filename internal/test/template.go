// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"fmt"
	"io/ioutil"
	"testing"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
)

// TemplateFuncs contains structs (and functions) used in templates.
type TemplateFuncs struct {
	Files Files
}

func GetTemplateFunctions(tb testing.TB) TemplateFuncs {
	tb.Helper()

	return TemplateFuncs{
		Files: Files{tb: tb},
	}
}

func GetTemplateUtilityFunctions() template.FuncMap {
	return sprig.TxtFuncMap()
}

type Files struct {
	tb testing.TB
}

func (f Files) Get(relativePath string) string {
	path := PathToDir(f.tb, relativePath)

	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("failed to read from %q: %w", relativePath, err))
	}

	return string(fileBytes)
}
