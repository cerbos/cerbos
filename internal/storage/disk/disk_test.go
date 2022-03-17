// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/internal"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestReloadable(t *testing.T) {
	storeDir := t.TempDir()
	store := mkStore(t, storeDir, false)

	watchingStoreDir := t.TempDir()
	watchingStore := mkStore(t, watchingStoreDir, true)

	internal.TestSuiteReloadable(store, false, mkPoliciesToStoreFn(t, storeDir))(t)
	internal.TestSuiteReloadable(watchingStore, true, mkPoliciesToStoreFn(t, watchingStoreDir))(t)
}

func mkStore(t *testing.T, dir string, watchForChanges bool) *Store {
	t.Helper()

	mkDirs(t, dir)
	store, err := NewStore(context.Background(), &Conf{Directory: dir, WatchForChanges: watchForChanges})
	require.NoError(t, err)

	return store
}

func mkPoliciesToStoreFn(t *testing.T, destStoreDir string) internal.PoliciesToStoreFn {
	t.Helper()
	policiesDir := test.PathToDir(t, "store")
	return func() error {
		err := filepath.WalkDir(policiesDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				switch d.Name() {
				case util.TestDataDirectory:
					return fs.SkipDir
				default:
					return nil
				}
			}

			in, err := os.Open(path)
			if err != nil {
				return err
			}
			defer in.Close()

			out, err := os.Create(filepath.Join(destStoreDir, filepath.Base(filepath.Dir(path)), filepath.Base(path)))
			if err != nil {
				return err
			}
			defer out.Close()

			_, err = io.Copy(out, in)
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}

		return nil
	}
}

func mkDirs(t *testing.T, storeDir string) {
	t.Helper()

	err := os.Mkdir(filepath.Join(storeDir, schema.Directory), os.ModePerm)
	require.NoError(t, err)
	err = os.Mkdir(filepath.Join(storeDir, "derived_roles"), os.ModePerm)
	require.NoError(t, err)
	err = os.Mkdir(filepath.Join(storeDir, "principal_policies"), os.ModePerm)
	require.NoError(t, err)
	err = os.Mkdir(filepath.Join(storeDir, "resource_policies"), os.ModePerm)
	require.NoError(t, err)
}
