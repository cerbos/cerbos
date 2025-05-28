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
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
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

			require.Contains(t, rt.meta, modID)

			require.NotContains(t, rt.policyDerivedRoles, modID)

			require.Contains(t, rt.resourceScopeMap, scope)
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

			exists, queried := rt.storeQueryRegister.get(modID)
			require.False(t, queried)
			require.False(t, exists)
		})

		t.Run("lazy load and delete", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			// Registry stores the modID after LazyLoads
			require.NoError(t, rt.LazyLoadResourcePolicy(ctx, resource, version, scope, []string{role}))
			exists, queried := rt.storeQueryRegister.get(modID)
			require.True(t, queried)
			require.True(t, exists)
			exists, queried = rt.storeQueryRegister.get(nonexistentRolePolicyModID)
			require.True(t, queried)
			require.False(t, exists)

			checkIndexes(t)

			rt.processPolicyEvent(storage.Event{
				Kind:     storage.EventDeleteOrDisablePolicy,
				PolicyID: modID,
			})

			require.Empty(t, rt.primaryIdx)
			require.Empty(t, rt.meta)
			require.Empty(t, rt.policyDerivedRoles)
			require.Empty(t, rt.resourceScopeMap)
			require.Empty(t, rt.scopeScopePermissions)
			// we keep the registry entry but set it to `false`
			require.Equal(t, 2, rt.storeQueryRegister.length())
			exists, queried = rt.storeQueryRegister.get(modID)
			require.True(t, queried)
			require.False(t, exists)
			require.True(t, rt.storeQueryRegister.contains(nonexistentRolePolicyModID))
		})
	})

	t.Run("principal policy", func(t *testing.T) {
		principal := "terry_tibbs"
		version := "default"
		scope := ""
		resource := "equipment_request"
		action := "create"

		modID := namer.PrincipalPolicyModuleID(principal, version, scope)

		// version -> scope -> role -> action -> []rows
		checkIndexes := func(t *testing.T) {
			t.Helper()

			require.Contains(t, rt.primaryIdx, version)
			require.Contains(t, rt.primaryIdx[version], scope)
			// Principal policies use "*" as the role to match any role
			actionMap, exists := rt.primaryIdx[version][scope].GetWithLiteral("*")
			require.True(t, exists)
			rows, exists := actionMap.GetWithLiteral(action)
			require.True(t, exists)
			require.Len(t, rows, 1)

			require.Contains(t, rt.meta, modID)

			require.Contains(t, rt.principalScopeMap, scope)
			scopePermissions, exists := rt.scopeScopePermissions[scope]
			require.True(t, exists)
			require.Equal(t, scopePermissions, policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT)

			// Verify the principal field is correctly set
			for _, row := range rows {
				require.Equal(t, principal, row.Principal)
				require.Equal(t, policy.PrincipalKind, row.PolicyKind)
			}
		}

		t.Run("add policy caches", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			rps, err := compiler.GetFirstMatch(ctx, []namer.ModuleID{modID})
			require.NoError(t, err)

			require.NoError(t, rt.addPolicy(rps))

			checkIndexes(t)

			exists, queried := rt.storeQueryRegister.get(modID)
			require.False(t, queried)
			require.False(t, exists)
		})

		t.Run("lazy load and delete", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			// Registry stores the modID after LazyLoads
			require.NoError(t, rt.LazyLoadPrincipalPolicy(ctx, principal, version, scope))
			exists, queried := rt.storeQueryRegister.get(modID)
			require.True(t, queried)
			require.True(t, exists)

			checkIndexes(t)

			// Check principal policy exists for the given scope
			exists = rt.ScopedPrincipalExists(version, []string{scope})
			require.True(t, exists)

			// Test scope-based access
			rows := rt.GetRows(version, resource, []string{scope}, []string{"any_role"}, []string{action})
			require.NotEmpty(t, rows)
			for _, row := range rows {
				require.Equal(t, principal, row.Principal)
				require.Equal(t, policy.PrincipalKind, row.PolicyKind)
			}

			// Test that Matches correctly identifies principal policies
			for _, row := range rows {
				matches := row.Matches(policy.PrincipalKind, scope, action, principal, []string{"any_role"})
				require.True(t, matches)

				// Should not match a different principal
				matches = row.Matches(policy.PrincipalKind, scope, action, "different.user@example.com", []string{"any_role"})
				require.False(t, matches)
			}

			// Delete the policy
			rt.processPolicyEvent(storage.Event{
				Kind:     storage.EventDeleteOrDisablePolicy,
				PolicyID: modID,
			})

			require.Empty(t, rt.primaryIdx)
			require.Empty(t, rt.meta)
			require.Empty(t, rt.policyDerivedRoles)
			require.Empty(t, rt.principalScopeMap)
			require.Empty(t, rt.scopeScopePermissions)
			// not deleted, just set to `false`
			exists, queried = rt.storeQueryRegister.get(modID)
			require.True(t, queried)
			require.False(t, exists)

			// Confirm principal policy no longer exists
			exists = rt.ScopedPrincipalExists(version, []string{scope})
			require.False(t, exists)
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

			require.Contains(t, rt.meta, modID)

			require.Contains(t, rt.resourceScopeMap, scope)
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

			exists, queried := rt.storeQueryRegister.get(modID)
			require.False(t, queried)
			require.False(t, exists)
		})

		t.Run("lazy load and delete", func(t *testing.T) {
			t.Cleanup(func() {
				rt.purge()
			})

			// Registry stores the modID after LazyLoads
			require.NoError(t, rt.LazyLoadResourcePolicy(ctx, resource, version, scope, []string{role}))
			// A store miss for the resource policy with lenientScopeSearch allows pre-optimised assertion that no
			// resource policies exist in any scopes, hence the extra keys in the storeQueryRegister.
			require.Equal(t, 7, rt.storeQueryRegister.length())
			exists, queried := rt.storeQueryRegister.get(modID)
			require.True(t, queried)
			require.True(t, exists)
			// all nonexistent resource policy FQNs
			exists, queried = rt.storeQueryRegister.get(namer.ResourcePolicyModuleID(resource, version, scope))
			require.True(t, queried)
			require.False(t, exists)
			for s := range namer.ScopeParents(scope) {
				exists, queried = rt.storeQueryRegister.get(namer.ResourcePolicyModuleID(resource, version, s))
				require.True(t, queried)
				require.False(t, exists)
			}
			// Missing role policy in first parent scope (the search breaks after this with "not found")
			exists, queried = rt.storeQueryRegister.get(namer.RolePolicyModuleID(role, "acme.hr.uk"))
			require.True(t, queried)
			require.False(t, exists)

			checkIndexes(t)

			rt.processPolicyEvent(storage.Event{
				Kind:     storage.EventDeleteOrDisablePolicy,
				PolicyID: modID,
			})

			require.Empty(t, rt.primaryIdx)
			require.Empty(t, rt.meta)
			require.Empty(t, rt.policyDerivedRoles)
			require.Empty(t, rt.resourceScopeMap)
			require.Empty(t, rt.scopeScopePermissions)
			require.Empty(t, rt.parentRoles)
			require.Empty(t, rt.parentRoleAncestorsCache)
			// not deleted, just set to `false`
			require.Equal(t, 7, rt.storeQueryRegister.length())
			exists, queried = rt.storeQueryRegister.get(modID)
			require.True(t, queried)
			require.False(t, exists)
		})
	})

	t.Run("resource policy with derived role", func(t *testing.T) {
		t.Cleanup(func() {
			rt.purge()
		})

		resource := "leave_request"
		version := "default"
		scope := "acme"

		require.NoError(t, rt.LazyLoadResourcePolicy(ctx, resource, version, scope, []string{}))

		modID := namer.ResourcePolicyModuleID(resource, version, scope)
		baseModID := namer.ResourcePolicyModuleID(resource, version, "")

		alphaModID := namer.DerivedRolesModuleID("alpha")
		betaModID := namer.DerivedRolesModuleID("beta")

		// at scope "acme"
		drs, exists := rt.policyDerivedRoles[modID]
		require.True(t, exists)
		require.Contains(t, drs, "employee_that_owns_the_record")
		require.Contains(t, drs, "any_employee")
		// no rules in the "" scope policy reference a derived role, hence it doesn't exist
		_, exists = rt.policyDerivedRoles[baseModID]
		require.False(t, exists)

		alpha, exists := rt.derivedRolePolicies[alphaModID]
		require.True(t, exists)
		require.Contains(t, alpha, modID)
		beta, exists := rt.derivedRolePolicies[betaModID]
		require.True(t, exists)
		require.Contains(t, beta, modID)

		// trigger (empty) update on `alpha` derived role policy
		rt.processPolicyEvent(storage.Event{
			Kind:     storage.EventAddOrUpdatePolicy,
			PolicyID: alphaModID,
		})

		// the resource policy that references the derived role at scope "acme" should be deleted.
		// the resource policy at scope "" remains (it's rules didn't reference a derived role).
		require.Empty(t, rt.policyDerivedRoles)
		require.NotContains(t, rt.primaryIdx[version], scope)
		require.NotContains(t, rt.meta, modID)
		require.NotContains(t, rt.resourceScopeMap, scope)
		require.NotContains(t, rt.scopeScopePermissions, scope)
		// referencing resource policy is deleted to prompt fresh retrieval
		require.False(t, rt.storeQueryRegister.contains(modID))
		// non-referencing resource policy is still present and untouched
		exists, queried := rt.storeQueryRegister.get(baseModID)
		require.True(t, queried)
		require.True(t, exists)

		require.NotContains(t, rt.derivedRolePolicies, alphaModID)
		require.Contains(t, rt.derivedRolePolicies, betaModID)
	})
}
