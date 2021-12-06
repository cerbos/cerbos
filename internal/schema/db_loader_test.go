// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/test"
)

func TestDBLoader(t *testing.T) {
	dir := test.PathToDir(t, filepath.Join("schema", "fs", "_schemas"))

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	var store storage.Store
	store, err := sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: "file::memory:?_fk=true"})
	require.NoError(t, err)

	ms, ok := store.(storage.MutableStore)
	require.True(t, ok)

	test.AddSchemasToStore(t, dir, ms)
	require.NoError(t, err)

	loader := schema.NewDBLoader(getLoadURL(ms))

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
	})
}

func getLoadURL(ms storage.MutableStore) schema.LoadURLFn {
	return func(schemaUrl string) (io.ReadCloser, error) {
		u, err := url.Parse(schemaUrl)
		if err != nil {
			return nil, err
		}

		if u.Scheme == schema.URLScheme {
			relativePath := strings.TrimPrefix(u.Path, "/")

			reader, err := ms.LoadSchema(context.TODO(), relativePath)
			if err != nil {
				return nil, err
			}

			s, err := ioutil.ReadAll(reader)
			if err != nil {
				return nil, err
			}

			return io.NopCloser(bytes.NewReader(s)), nil
		}

		return nil, fmt.Errorf("invalid schema url")
	}
}
