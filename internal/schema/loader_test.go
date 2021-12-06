// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/test"
)

func TestFSLoader(t *testing.T) {
	fsDir := test.PathToDir(t, filepath.Join("schema", "fs"))
	fsys := os.DirFS(fsDir)
	loader := schema.NewFSLoader(fsys, ".")

	t.Run("schema_with_relative_refs", func(t *testing.T) {
		have, err := loader.Load(context.Background(), "cerbos:///customer_relative.json")
		require.NoError(t, err)
		require.NotNil(t, have)
	})

	t.Run("schema_with_absolute_refs", func(t *testing.T) {
		have, err := loader.Load(context.Background(), "cerbos:///customer_absolute.json")
		require.NoError(t, err)
		require.NotNil(t, have)
	})

	t.Run("schema_with_bad_refs", func(t *testing.T) {
		_, err := loader.Load(context.Background(), "cerbos:///customer_bad.json")
		require.Error(t, err)
	})

	t.Run("invalid_schema", func(t *testing.T) {
		_, err := loader.Load(context.Background(), "cerbos:///invalid.json")
		require.Error(t, err)
	})

	t.Run("non_existent_schema", func(t *testing.T) {
		_, err := loader.Load(context.Background(), "cerbos:///blah.json")
		require.Error(t, err)
		require.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("schema_in_sub_dir", func(t *testing.T) {
		have, err := loader.Load(context.Background(), "cerbos:///subdir/customer_absolute.json")
		require.NoError(t, err)
		require.NotNil(t, have)
	})

	t.Run("load_directly_from_file", func(t *testing.T) {
		have, err := loader.Load(context.Background(), filepath.Join(fsDir, schema.Directory, "customer_absolute.json"))
		require.NoError(t, err)
		require.NotNil(t, have)
	})
}
