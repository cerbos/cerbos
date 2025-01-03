// Copyright 2021-2025 Zenauth Ltd.
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

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestIndexLoadPolicy(t *testing.T) {
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
		"role_policies/policy_01.yaml",
		"role_policies/policy_02.yaml",
	}

	testLoadPolicy := func(t *testing.T, path string) {
		t.Helper()

		base := test.PathToDir(t, path)
		fsys, err := util.OpenDirectoryFS(base)
		require.NoError(t, err)
		idx, err := index.Build(context.Background(), fsys)
		require.NoError(t, err)
		t.Cleanup(func() { _ = idx.Close() })

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
				require.Equal(t, policyFiles[idx], p.Metadata.StoreIdentifier)
			}
		})

		t.Run("should have the hash in the metadata of the policies", func(t *testing.T) {
			policies, err := idx.LoadPolicy(context.Background(), policyFiles...)
			require.NoError(t, err)

			for _, p := range policies {
				require.Equal(t, wrapperspb.UInt64(util.HashPB(p, policy.IgnoreHashFields)), p.Metadata.Hash)
			}
		})
	}

	t.Run("load policy", func(t *testing.T) {
		testLoadPolicy(t, "store")
	})
	t.Run("load policy zip", func(t *testing.T) {
		testLoadPolicy(t, "store_archive/policies.zip")
	})
	t.Run("load policy tar", func(t *testing.T) {
		testLoadPolicy(t, "store_archive/policies.tar")
	})
	t.Run("load policy gzip", func(t *testing.T) {
		testLoadPolicy(t, "store_archive/policies.tgz")
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
		"principal.json",
		"resources/leave_request.json",
		"resources/purchase_order.json",
		"resources/salary_record.json",
	}, ids)
}

func TestIndexGetFirstMatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fsys := os.DirFS(test.PathToDir(t, "."))

	idx, err := index.Build(ctx, fsys, index.WithRootDir("store"))
	require.NoError(t, err)

	testCases := []struct {
		name   string
		modIDs []namer.ModuleID
		want   func() namer.ModuleID
	}{
		{
			name:   "resource_policy/strict/non_existent",
			modIDs: namer.ScopedResourcePolicyModuleIDs("leave_request", "default", "acme.hr.france.marseille", false),
		},
		{
			name:   "resource_policy/strict/existent",
			modIDs: namer.ScopedResourcePolicyModuleIDs("leave_request", "default", "acme.hr", false),
			want: func() namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.ResourcePolicyFQN("leave_request", "default", "acme.hr"))
			},
		},
		{
			name:   "resource_policy/lenient/some_leaf_scopes_missing",
			modIDs: namer.ScopedResourcePolicyModuleIDs("leave_request", "default", "acme.hr.france.marseille", true),
			want: func() namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.ResourcePolicyFQN("leave_request", "default", "acme.hr"))
			},
		},
		{
			name:   "resource_policy/lenient/all_scopes_missing",
			modIDs: namer.ScopedResourcePolicyModuleIDs("leave_request", "default", "foo.bar.baz", true),
			want: func() namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.ResourcePolicyFQN("leave_request", "default", ""))
			},
		},
		{
			name:   "resource_policy/lenient/non_existent",
			modIDs: namer.ScopedResourcePolicyModuleIDs("leave_request", "blah", "blah", true),
		},
		{
			name:   "principal_policy/strict/non_existent",
			modIDs: namer.ScopedPrincipalPolicyModuleIDs("donald_duck", "default", "acme.hr.france.marseille", false),
		},
		{
			name:   "principal_policy/strict/existent",
			modIDs: namer.ScopedPrincipalPolicyModuleIDs("donald_duck", "default", "acme.hr", false),
			want: func() namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.PrincipalPolicyFQN("donald_duck", "default", "acme.hr"))
			},
		},
		{
			name:   "principal_policy/lenient/some_leaf_scopes_missing",
			modIDs: namer.ScopedPrincipalPolicyModuleIDs("donald_duck", "default", "acme.hr.france.marseille", true),
			want: func() namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.PrincipalPolicyFQN("donald_duck", "default", "acme.hr"))
			},
		},
		{
			name:   "principal_policy/lenient/all_scopes_missing",
			modIDs: namer.ScopedPrincipalPolicyModuleIDs("donald_duck", "default", "foo.bar.baz", true),
			want: func() namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.PrincipalPolicyFQN("donald_duck", "default", ""))
			},
		},
		{
			name:   "principal_policy/lenient/non_existent",
			modIDs: namer.ScopedPrincipalPolicyModuleIDs("donald_duck", "blah", "blah", true),
		},
		{
			name:   "role_policy/strict/non_existent",
			modIDs: []namer.ModuleID{namer.RolePolicyModuleID("acme_super_admin", "acme.hr.uk")},
		},
		{
			name:   "role_policy/strict/existent",
			modIDs: []namer.ModuleID{namer.RolePolicyModuleID("acme_jr_admin", "acme.hr.uk")},
			want: func() namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.RolePolicyFQN("acme_jr_admin", "acme.hr.uk"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			have, err := idx.GetFirstMatch(tc.modIDs)
			require.NoError(t, err)
			if tc.want == nil {
				require.Nil(t, have)
			} else {
				want := tc.want()
				require.Equal(t, want, have.ModID)
			}
		})
	}
}

func TestIndexGetDependents(t *testing.T) {
	idx, err := index.Build(context.Background(), os.DirFS(test.PathToDir(t, "store")))
	require.NoError(t, err)

	modID := namer.ExportVariablesModuleID("foobar")
	dependents, err := idx.GetDependents(modID)
	require.NoError(t, err)
	require.Len(t, dependents, 1)
	require.Contains(t, dependents, modID)
	require.ElementsMatch(t, []namer.ModuleID{
		namer.DerivedRolesModuleID("import_variables"),
		namer.PrincipalPolicyModuleID("scrooge_mcduck", "default", ""),
		namer.ResourcePolicyModuleID("import_variables", "default", ""),
		namer.ResourcePolicyModuleID("import_derived_roles_that_import_variables", "default", ""),
	}, dependents[modID])
}
