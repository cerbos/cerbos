// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func TestRuleTable(t *testing.T) {
	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(t.Context())
	defer cancelFunc()

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	schemaConf := schema.NewConf(schema.EnforcementNone)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	compiler := compile.NewManagerFromDefaultConf(ctx, store, schemaMgr)

	rt := NewRuleTable(compiler)

	t.Run("resource policy", func(t *testing.T) {
		resource := "leave_request"
		version := "default"
		scope := ""
		role := "admin"

		nonexistentRolePolicyModID := namer.RolePolicyModuleID(role, scope)

		modID := namer.ResourcePolicyModuleID(resource, version, scope)

		// version -> scope -> role -> action -> []rows
		checkIndexes := func(t *testing.T) {
			t.Helper()

			require.Contains(t, rt.primaryIdx, version)
			require.Contains(t, rt.primaryIdx[version], scope)
			actionMap, exists := rt.primaryIdx[version][scope].GetWithLiteral(role)
			require.True(t, exists)
			rows, exists := actionMap.GetWithLiteral("*")
			require.True(t, exists)
			require.Len(t, rows, 1)

			require.Contains(t, rt.scopedResourceIdx, version)
			require.Contains(t, rt.scopedResourceIdx[version], scope)
			_, exists = rt.scopedResourceIdx[version][scope].GetWithLiteral("leave_request")
			require.True(t, exists)

			require.Contains(t, rt.schemas, modID)
			require.Contains(t, rt.meta, modID)

			require.Contains(t, rt.policyDerivedRoles, modID)
			require.Empty(t, rt.policyDerivedRoles[modID])

			require.Contains(t, rt.scopeMap, scope)
			scopePermissions, exists := rt.scopeScopePermissions[scope]
			require.True(t, exists)
			require.Equal(t, scopePermissions, policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT)
		}

		t.Run("add policy caches", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			rps, err := compiler.GetFirstMatch(ctx, []namer.ModuleID{modID})
			require.NoError(t, err)

			require.NoError(t, rt.addPolicy(rps))

			checkIndexes(t)

			exists, queried := rt.storeQueryRegister[modID]
			require.False(t, queried)
			require.False(t, exists)
		})

		t.Run("lazy load and delete", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			// Registry stores the modID after LazyLoads
			require.NoError(t, rt.LazyLoad(ctx, resource, version, scope, []string{role}))
			exists, queried := rt.storeQueryRegister[modID]
			require.True(t, queried)
			require.True(t, exists)
			exists, queried = rt.storeQueryRegister[nonexistentRolePolicyModID]
			require.True(t, queried)
			require.False(t, exists)

			checkIndexes(t)

			rt.deletePolicy(modID)

			require.Empty(t, rt.primaryIdx)
			require.Empty(t, rt.scopedResourceIdx)
			require.Empty(t, rt.schemas)
			require.Empty(t, rt.meta)
			require.Empty(t, rt.policyDerivedRoles)
			require.Empty(t, rt.scopeMap)
			require.Empty(t, rt.scopeScopePermissions)
			// we keep the registry entry but set it to `false`
			require.Len(t, rt.storeQueryRegister, 2)
			exists, queried = rt.storeQueryRegister[modID]
			require.True(t, queried)
			require.False(t, exists)
			require.Contains(t, rt.storeQueryRegister, nonexistentRolePolicyModID)
		})
	})

	t.Run("role policy", func(t *testing.T) {
		role := "acme_london_employee"
		version := "default"
		scope := "acme.hr.uk.london"
		resource := "*"

		modID := namer.RolePolicyModuleID(role, scope)

		checkIndexes := func(t *testing.T) {
			t.Helper()

			// version -> scope -> role -> action -> []rows
			require.Contains(t, rt.primaryIdx, version)
			require.Contains(t, rt.primaryIdx[version], scope)
			actionMap, exists := rt.primaryIdx[version][scope].GetWithLiteral(role)
			require.True(t, exists)
			// REQUIRE_PARENTAL_CONSENT actions get stored in the shared AllowActions cache
			rows, exists := actionMap.GetWithLiteral(allowActionsIdxKey)
			require.True(t, exists)
			// two rules exist for `acme_london_employee`
			require.Len(t, rows, 2)

			require.Contains(t, rt.scopedResourceIdx, version)
			require.Contains(t, rt.scopedResourceIdx[version], scope)
			_, exists = rt.scopedResourceIdx[version][scope].GetWithLiteral(resource)
			require.True(t, exists)

			require.Contains(t, rt.meta, modID)

			require.Contains(t, rt.scopeMap, scope)
			_, exists = rt.scopeScopePermissions[scope]
			// role policies don't have a scope permissions setting
			require.False(t, exists)

			// warm up the parent roles cache
			rt.GetParentRoles(scope, []string{role})
			require.Contains(t, rt.parentRoles, scope)
			require.Contains(t, rt.parentRoles[scope], role)
			require.Contains(t, rt.parentRoleAncestorsCache, scope)
			require.Contains(t, rt.parentRoleAncestorsCache[scope], role)
		}

		t.Run("add policy caches", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			rps, err := compiler.GetFirstMatch(ctx, []namer.ModuleID{modID})
			require.NoError(t, err)

			require.NoError(t, rt.addPolicy(rps))

			checkIndexes(t)

			exists, queried := rt.storeQueryRegister[modID]
			require.False(t, queried)
			require.False(t, exists)
		})

		t.Run("lazy load and delete", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			// Registry stores the modID after LazyLoads
			require.NoError(t, rt.LazyLoad(ctx, resource, version, scope, []string{role}))
			// A store miss for the resource policy with lenientScopeSearch allows pre-optimised assertion that no
			// resource policies exist in any scopes, hence the extra keys in the storeQueryRegister.
			require.Len(t, rt.storeQueryRegister, 7)
			exists, queried := rt.storeQueryRegister[modID]
			require.True(t, queried)
			require.True(t, exists)
			// all nonexistent resource policy FQNs
			exists, queried = rt.storeQueryRegister[namer.ResourcePolicyModuleID(resource, version, scope)]
			require.True(t, queried)
			require.False(t, exists)
			for s := range namer.ScopeParents(scope) {
				exists, queried = rt.storeQueryRegister[namer.ResourcePolicyModuleID(resource, version, s)]
				require.True(t, queried)
				require.False(t, exists)
			}
			// Missing role policy in first parent scope (the search breaks after this with "not found")
			exists, queried = rt.storeQueryRegister[namer.RolePolicyModuleID(role, "acme.hr.uk")]
			require.True(t, queried)
			require.False(t, exists)

			checkIndexes(t)

			rt.deletePolicy(modID)

			require.Empty(t, rt.primaryIdx)
			require.Empty(t, rt.scopedResourceIdx)
			require.Empty(t, rt.schemas)
			require.Empty(t, rt.meta)
			require.Empty(t, rt.policyDerivedRoles)
			require.Empty(t, rt.scopeMap)
			require.Empty(t, rt.scopeScopePermissions)
			require.Empty(t, rt.parentRoles)
			require.Empty(t, rt.parentRoleAncestorsCache)
			// not deleted, just set to `false`
			require.Len(t, rt.storeQueryRegister, 7)
			exists, queried = rt.storeQueryRegister[modID]
			require.True(t, queried)
			require.False(t, exists)
		})
	})
}
