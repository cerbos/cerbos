// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage/internal"
	"github.com/cerbos/cerbos/internal/test"
)

func TestReloadable(t *testing.T) {
	storeDir := t.TempDir()
	store := mkStore(t, storeDir)

	internal.TestSuiteReloadable(store, nil, mkAddFn(t, storeDir), mkDeleteFn(t, storeDir))(t)
}

func mkStore(t *testing.T, dir string) *Store {
	t.Helper()

	store, err := NewStore(context.Background(), &Conf{Directory: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	return store
}

func mkDeleteFn(t *testing.T, storeDir string) internal.MutateStoreFn {
	t.Helper()

	return func() error {
		dir, err := os.ReadDir(storeDir)
		if err != nil {
			return fmt.Errorf("failed to read directory while deleting from the store: %w", err)
		}
		for _, d := range dir {
			err = os.RemoveAll(path.Join([]string{storeDir, d.Name()}...))
			if err != nil {
				return fmt.Errorf("failed to remove contents while deleting from the store: %w", err)
			}
		}

		return nil
	}
}

func mkAddFn(t *testing.T, storeDir string) internal.MutateStoreFn {
	t.Helper()

	return func() error {
		err := test.FindPolicyFiles(t, "store", func(path string) error {
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			defer in.Close()

			pathToFile := filepath.Join(storeDir, filepath.Base(filepath.Dir(path)), filepath.Base(path))
			err = os.MkdirAll(filepath.Dir(pathToFile), 0o744)
			if err != nil {
				return err
			}

			out, err := os.Create(pathToFile)
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
