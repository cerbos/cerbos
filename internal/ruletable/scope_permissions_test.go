// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/policy/scopeperms"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	overrideParent  = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
	parentalConsent = policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
	unspecifiedPerm = policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED
)

// staticLoader serves pre-compiled policy sets.
type staticLoader struct {
	sets []*runtimev1.RunnablePolicySet
}

func (l staticLoader) GetFirstMatch(_ context.Context, ids []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	for _, id := range ids {
		for _, s := range l.sets {
			if namer.GenModuleIDFromFQN(s.Fqn) == id {
				return s, nil
			}
		}
	}

	return nil, nil
}

func (l staticLoader) GetAll(context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	return l.sets, nil
}

func (l staticLoader) GetAllMatching(ctx context.Context, ids []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	var out []*runtimev1.RunnablePolicySet
	for _, id := range ids {
		if s, _ := l.GetFirstMatch(ctx, []namer.ModuleID{id}); s != nil {
			out = append(out, s)
		}
	}

	return out, nil
}

func (staticLoader) Source() *auditv1.PolicySource { return nil }

func scopedResourcePolicy(resource, scope string, sp policyv1.ScopePermissions) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource:         resource,
				Version:          "default",
				Scope:            scope,
				ScopePermissions: sp,
				Rules: []*policyv1.ResourceRule{
					{
						Actions: []string{"view"},
						Roles:   []string{"user"},
						Effect:  effectv1.Effect_EFFECT_ALLOW,
					},
				},
			},
		},
	}
}

func compilePolicy(t *testing.T, p *policyv1.Policy, ancestors ...*policyv1.Policy) *runtimev1.RunnablePolicySet {
	t.Helper()

	modID := namer.GenModuleID(p)
	cu := &policy.CompilationUnit{ModID: modID}
	cu.AddDefinition(modID, p, parser.SourceCtx{})
	for _, a := range ancestors {
		cu.AddDefinition(namer.GenModuleID(a), a, parser.SourceCtx{})
	}

	rps, err := compile.Compile(cu, schema.NewNopManager())
	require.NoError(t, err)

	return rps
}

func requireConflict(t *testing.T, err error, scope string) {
	t.Helper()

	var conflictsErr *scopeperms.ConflictsError
	require.ErrorAs(t, err, &conflictsErr)
	require.Len(t, conflictsErr.Conflicts, 1)
	require.Equal(t, scope, conflictsErr.Conflicts[0].Scope)
}

func TestScopePermissionsConflicts(t *testing.T) {
	toolRootPolicy := scopedResourcePolicy("tool", "", unspecifiedPerm)
	recordRootPolicy := scopedResourcePolicy("record", "", unspecifiedPerm)
	toolRoot := compilePolicy(t, toolRootPolicy)
	toolCompany := compilePolicy(t, scopedResourcePolicy("tool", "company", unspecifiedPerm), toolRootPolicy)
	recordRoot := compilePolicy(t, recordRootPolicy)
	recordCompany := compilePolicy(t, scopedResourcePolicy("record", "company", parentalConsent), recordRootPolicy)

	agreeing := []*runtimev1.RunnablePolicySet{toolRoot, toolCompany, recordRoot}
	conflicting := []*runtimev1.RunnablePolicySet{toolRoot, toolCompany, recordRoot, recordCompany}

	t.Run("full_build_from_loader", func(t *testing.T) {
		_, err := ruletable.NewRuleTableFromLoader(t.Context(), staticLoader{sets: conflicting})
		requireConflict(t, err, "company")

		rt, err := ruletable.NewRuleTableFromLoader(t.Context(), staticLoader{sets: agreeing})
		require.NoError(t, err)
		require.Equal(t, overrideParent, rt.GetScopeScopePermissions("company"))
	})

	t.Run("build_from_proto", func(t *testing.T) {
		protoRT := ruletable.NewProtoRuletable()
		require.NoError(t, ruletable.LoadPolicies(t.Context(), protoRT, staticLoader{sets: conflicting}))

		_, err := ruletable.NewRuleTable(protoRT)
		requireConflict(t, err, "company")
	})

	t.Run("incremental", func(t *testing.T) {
		rt, err := ruletable.NewRuleTableFromLoader(t.Context(), staticLoader{sets: agreeing})
		require.NoError(t, err)

		mgr, err := ruletable.NewRuleTableManager(rt, staticLoader{sets: conflicting}, schema.NewNopManager())
		require.NoError(t, err)

		recordCompanyID := namer.GenModuleIDFromFQN(recordCompany.Fqn)
		toolCompanyID := namer.GenModuleIDFromFQN(toolCompany.Fqn)

		// A conflicting policy is rejected and the table is left untouched.
		mgr.OnStorageEvent(storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, recordCompanyID))
		require.Nil(t, mgr.GetMeta(recordCompany.Fqn))
		require.NotNil(t, mgr.GetMeta(toolCompany.Fqn))
		require.Equal(t, overrideParent, mgr.GetScopeScopePermissions("company"))

		// Removing the other side of the conflict makes room for it.
		mgr.OnStorageEvent(storage.NewPolicyEvent(storage.EventDeleteOrDisablePolicy, toolCompanyID))
		mgr.OnStorageEvent(storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, recordCompanyID))
		require.NotNil(t, mgr.GetMeta(recordCompany.Fqn))
		require.Equal(t, parentalConsent, mgr.GetScopeScopePermissions("company"))

		// Re-adding the removed policy is now the conflicting change.
		mgr.OnStorageEvent(storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, toolCompanyID))
		require.Nil(t, mgr.GetMeta(toolCompany.Fqn))
		require.Equal(t, parentalConsent, mgr.GetScopeScopePermissions("company"))
	})

	t.Run("updating_own_setting_is_not_a_conflict", func(t *testing.T) {
		rt, err := ruletable.NewRuleTableFromLoader(t.Context(), staticLoader{sets: agreeing})
		require.NoError(t, err)

		toolCompanyConsent := compilePolicy(t, scopedResourcePolicy("tool", "company", parentalConsent), toolRootPolicy)
		mgr, err := ruletable.NewRuleTableManager(rt, staticLoader{sets: []*runtimev1.RunnablePolicySet{toolCompanyConsent}}, schema.NewNopManager())
		require.NoError(t, err)

		mgr.OnStorageEvent(storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, namer.GenModuleIDFromFQN(toolCompanyConsent.Fqn)))
		require.Equal(t, parentalConsent, mgr.GetScopeScopePermissions("company"))
	})
}
