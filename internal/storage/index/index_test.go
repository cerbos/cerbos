// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package index_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestIndexLoadPolicy(t *testing.T) {
	base := test.PathToDir(t, "store")
	fsys := os.DirFS(base)
	idx, err := index.Build(context.Background(), fsys)
	require.NoError(t, err)

	policyFiles := mkListOfFiles(t, "store", base)

	t.Run("load policy", func(t *testing.T) {
		t.Run("should load the policies", func(t *testing.T) {
			policies, err := idx.LoadPolicy(context.Background(), policyFiles...)
			require.NoError(t, err)
			require.Len(t, policies, len(policyFiles))
		})

		t.Run("should have not empty metadata in the policies", func(t *testing.T) {
			policies, err := idx.LoadPolicy(context.Background(), policyFiles...)
			require.NoError(t, err)

			for _, p := range policies {
				require.NotEmpty(t, p.Metadata)
			}
		})

		t.Run("should have the store identifier in the metadata of the policies", func(t *testing.T) {
			policies, err := idx.LoadPolicy(context.Background(), policyFiles...)
			require.NoError(t, err)

			for idx, p := range policies {
				require.Equal(t, policyFiles[idx], p.Metadata.StoreIdentifer)
			}
		})

		t.Run("should have the hash in the metadata of the policies", func(t *testing.T) {
			policies, err := idx.LoadPolicy(context.Background(), policyFiles...)
			require.NoError(t, err)

			for _, p := range policies {
				require.Equal(t, wrapperspb.UInt64(util.HashPB(p, policy.IgnoreHashFields)), p.Metadata.Hash)
			}
		})
	})
}

// mkListOfFiles generates a list of policy files under the given filesystem and returns the list.
func mkListOfFiles(t *testing.T, dir, base string) []string {
	t.Helper()

	var list []string
	err := test.FindPolicyFiles(t, dir, func(path string) error {
		relPath, err := filepath.Rel(base, path)
		require.NoError(t, err)
		list = append(list, relPath)
		return nil
	})
	require.NoError(t, err)

	return list
}
