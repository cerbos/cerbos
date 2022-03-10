// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONSchemasAreValid(t *testing.T) {
	var paths []string

	err := filepath.WalkDir("jsonschema", func(path string, _ fs.DirEntry, err error) error {
		if strings.HasSuffix(path, ".schema.json") {
			paths = append(paths, path)
		}

		return err
	})

	require.NoError(t, err, "failed to walk schema directory")
	require.NotEmpty(t, paths, "didn't find any schemas")

	compiler := jsonschema.NewCompiler()

	for _, path := range paths {
		_, err := compiler.Compile(path)
		assert.NoError(t, err, "invalid schema %q", path)
	}
}
