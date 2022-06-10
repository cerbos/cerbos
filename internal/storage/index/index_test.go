// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package index_test

import (
	"context"
	"os"
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

	policyFiles := []string{
		"derived_roles/common_roles.yaml",
		"derived_roles/derived_roles_01.yaml",
		"derived_roles/derived_roles_02.yaml",
		"derived_roles/derived_roles_03.yaml",
		"principal_policies/policy_01.yaml",
		"principal_policies/policy_02.yaml",
		"principal_policies/policy_02_acme.hr.yaml",
		"principal_policies/policy_02_acme.yaml",
		"resource_policies/policy_01.yaml",
		"resource_policies/policy_02.yaml",
		"resource_policies/policy_03.yaml",
		"resource_policies/policy_04.yaml",
		"resource_policies/policy_05.yaml",
		"resource_policies/policy_05_acme.hr.uk.yaml",
		"resource_policies/policy_05_acme.hr.yaml",
		"resource_policies/policy_05_acme.yaml",
		"resource_policies/policy_06.yaml",
	}

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

func TestIndexListSchemaIDs(t *testing.T) {
	ctx := context.Background()
	fsys := os.DirFS(test.PathToDir(t, "."))

	idx, err := index.Build(ctx, fsys, index.WithRootDir("store"))
	require.NoError(t, err)

	ids, err := idx.ListSchemaIDs(ctx)
	require.NoError(t, err)

	require.Equal(t, []string{
		"leave_request.json",
		"principal.json",
		"purchase_order.json",
		"salary_record.json",
	}, ids)
}
