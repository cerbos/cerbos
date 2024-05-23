// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package internal

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/test"
)

const timeout = 2 * time.Second

//nolint:mnd
func TestSuite(store DBStorage) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		pp := policy.Wrap(test.GenPrincipalPolicy(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))
		ev := policy.Wrap(test.GenExportVariables(test.NoMod()))
		rpx := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("x", "x")))
		drx := policy.Wrap(test.GenDerivedRoles(test.PrefixAndSuffix("x", "x")))

		rpAcme := withScope(test.GenResourcePolicy(test.NoMod()), "acme")
		rpAcmeHR := withScope(test.GenResourcePolicy(test.NoMod()), "acme.hr")
		rpAcmeHRUK := withScope(test.GenResourcePolicy(test.NoMod()), "acme.hr.uk")
		ppAcme := withScope(test.GenPrincipalPolicy(test.NoMod()), "acme")
		ppAcmeHR := withScope(test.GenPrincipalPolicy(test.NoMod()), "acme.hr")

		drImportVariables := policy.Wrap(test.GenDerivedRoles(test.Suffix("_import_variables")))
		drImportVariables.GetDerivedRoles().Variables = &policyv1.Variables{Import: []string{ev.Name}}
		rpImportDerivedRolesThatImportVariables := policy.Wrap(test.GenResourcePolicy(test.Suffix("_import_derived_roles_that_import_variables")))
		rpImportDerivedRolesThatImportVariables.GetResourcePolicy().ImportDerivedRoles = []string{drImportVariables.Name}
		rpImportDerivedRolesThatImportVariables.GetResourcePolicy().Variables = nil

		rpDupe1 := policy.Wrap(test.GenResourcePolicy(test.Suffix("@foo")))
		rpDupe2 := policy.Wrap(test.GenResourcePolicy(test.Suffix("@@foo")))
		ppDupe1 := policy.Wrap(test.GenPrincipalPolicy(test.Suffix("@foo")))
		ppDupe2 := policy.Wrap(test.GenPrincipalPolicy(test.Suffix("@@foo")))
		drDupe1 := policy.Wrap(test.GenDerivedRoles(test.Suffix("@foo")))
		drDupe2 := policy.Wrap(test.GenDerivedRoles(test.Suffix("@@foo")))
		evDupe1 := policy.Wrap(test.GenExportVariables(test.Suffix("@foo")))
		evDupe2 := policy.Wrap(test.GenExportVariables(test.Suffix("@@foo")))

		xevx := policy.Wrap(test.GenExportVariables(test.PrefixAndSuffix("x", "x")))

		policyList := []policy.Wrapper{rp, pp, dr, ev, rpx, drx, rpAcme, rpAcmeHR, rpAcmeHRUK, ppAcme, ppAcmeHR, drImportVariables, rpImportDerivedRolesThatImportVariables, rpDupe1, ppDupe1, drDupe1, evDupe1, xevx}
		policyMap := make(map[string]policy.Wrapper)
		for _, p := range policyList {
			policyMap[namer.PolicyKeyFromFQN(p.FQN)] = p
		}

		sch := test.ReadSchemaFromFile(t, test.PathToDir(t, "store/_schemas/resources/leave_request.json"))
		const schID = "leave_request"

		addPolicies := func(t *testing.T) {
			t.Helper()

			checkEvents := storage.TestSubscription(store)
			require.NoError(t, store.AddOrUpdate(ctx, policyList...))

			wantEvents := []storage.Event{
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rp.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: pp.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: dr.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: ev.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpx.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: drx.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpAcme.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpAcmeHR.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpAcmeHRUK.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: ppAcme.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: ppAcmeHR.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: drImportVariables.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpImportDerivedRolesThatImportVariables.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpDupe1.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: ppDupe1.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: drDupe1.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: evDupe1.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: xevx.ID},
			}
			checkEvents(t, timeout, wantEvents...)

			stats := store.RepoStats(ctx)
			require.Equal(t, 7, stats.PolicyCount[policy.ResourceKind])
			require.Equal(t, 4, stats.PolicyCount[policy.PrincipalKind])
			require.Equal(t, 4, stats.PolicyCount[policy.DerivedRolesKind])
			require.Equal(t, 3, stats.PolicyCount[policy.ExportVariablesKind])
		}

		t.Run("add_or_update", func(t *testing.T) {
			t.Run("add", addPolicies)
			t.Run("update", addPolicies)
		})

		t.Run("add_id_collision", func(t *testing.T) {
			require.ErrorIs(t, store.AddOrUpdate(ctx, rpDupe2), storage.ErrPolicyIDCollision, "rpDupe2 not detected")
			require.ErrorIs(t, store.AddOrUpdate(ctx, ppDupe2), storage.ErrPolicyIDCollision, "ppDupe2 not detected")
			require.ErrorIs(t, store.AddOrUpdate(ctx, drDupe2), storage.ErrPolicyIDCollision, "drDupe2 not detected")
			require.ErrorIs(t, store.AddOrUpdate(ctx, evDupe2), storage.ErrPolicyIDCollision, "evDupe2 not detected")
		})

		t.Run("get_compilation_unit_for_resource_policy", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rp.ID)
			require.NoError(t, err)
			requireCompilationUnits(t, map[policy.Wrapper][]policy.Wrapper{
				rp: {rp, dr, ev},
			}, have)
		})

		t.Run("get_compilation_unit_for_resource_policy_that_imports_derived_roles_that_import_variables", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rpImportDerivedRolesThatImportVariables.ID)
			require.NoError(t, err)
			requireCompilationUnits(t, map[policy.Wrapper][]policy.Wrapper{
				rpImportDerivedRolesThatImportVariables: {rpImportDerivedRolesThatImportVariables, drImportVariables, ev},
			}, have)
		})

		t.Run("get_compilation_unit_for_principal_policy", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, pp.ID)
			require.NoError(t, err)
			requireCompilationUnits(t, map[policy.Wrapper][]policy.Wrapper{
				pp: {pp, ev},
			}, have)
		})

		t.Run("get_compilation_unit_for_scoped_resource_policy", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rpAcmeHRUK.ID)
			require.NoError(t, err)
			requireCompilationUnits(t, map[policy.Wrapper][]policy.Wrapper{
				rpAcmeHRUK: {rpAcmeHRUK, rpAcmeHR, rpAcme, rp, dr, ev},
			}, have)
		})

		t.Run("get_compilation_unit_for_scoped_principal_policy", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, ppAcmeHR.ID)
			require.NoError(t, err)
			requireCompilationUnits(t, map[policy.Wrapper][]policy.Wrapper{
				ppAcmeHR: {ppAcmeHR, ppAcme, pp, ev},
			}, have)
		})

		t.Run("get_multiple_compilation_units", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rp.ID, pp.ID, rpAcmeHRUK.ID)
			require.NoError(t, err)
			requireCompilationUnits(t, map[policy.Wrapper][]policy.Wrapper{
				rp:         {rp, dr, ev},
				pp:         {pp, ev},
				rpAcmeHRUK: {rpAcmeHRUK, rpAcmeHR, rpAcme, rp, dr, ev},
			}, have)
		})

		t.Run("get_non_existent_compilation_unit", func(t *testing.T) {
			p := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("y", "y")))
			have, err := store.GetCompilationUnits(ctx, p.ID)
			require.NoError(t, err)
			require.Empty(t, have)
		})

		t.Run("get_first_match_resource_policy", func(t *testing.T) {
			modIDs := namer.ScopedResourcePolicyModuleIDs(rpAcmeHR.Name, rpAcmeHR.Version, "acme.hr.france.marseille", true)
			have, err := store.GetFirstMatch(ctx, modIDs)
			require.NoError(t, err)
			requireCompilationUnit(t, rpAcmeHR.ID, []policy.Wrapper{rpAcmeHR, rpAcme, rp, dr, ev}, have)
		})

		t.Run("get_first_match_principal_policy", func(t *testing.T) {
			modIDs := namer.ScopedPrincipalPolicyModuleIDs(ppAcmeHR.Name, ppAcmeHR.Version, "acme.hr.france.marseille", true)
			have, err := store.GetFirstMatch(ctx, modIDs)
			require.NoError(t, err)
			requireCompilationUnit(t, ppAcmeHR.ID, []policy.Wrapper{ppAcmeHR, ppAcme, pp, ev}, have)
		})

		t.Run("get_first_match_non_existent", func(t *testing.T) {
			modIDs := namer.ScopedResourcePolicyModuleIDs("foo", "bar", "acme.hr.france.marseille", true)
			have, err := store.GetFirstMatch(ctx, modIDs)
			require.NoError(t, err)
			require.Nil(t, have)
		})

		t.Run("get_dependents", func(t *testing.T) {
			have, err := store.GetDependents(ctx, dr.ID, ev.ID)
			require.NoError(t, err)

			require.Len(t, have, 2)
			require.Contains(t, have, dr.ID)
			require.ElementsMatch(t, []namer.ModuleID{rp.ID, rpAcme.ID, rpAcmeHR.ID, rpAcmeHRUK.ID}, have[dr.ID])
			require.Contains(t, have, ev.ID)
			require.ElementsMatch(t, []namer.ModuleID{rp.ID, rpAcme.ID, rpAcmeHR.ID, rpAcmeHRUK.ID, pp.ID, ppAcme.ID, ppAcmeHR.ID, drImportVariables.ID, rpImportDerivedRolesThatImportVariables.ID}, have[ev.ID])
		})

		t.Run("get_policy", func(t *testing.T) {
			for _, want := range policyList {
				want := want
				t.Run(want.FQN, func(t *testing.T) {
					haveRes, err := store.LoadPolicy(ctx, namer.PolicyKeyFromFQN(want.FQN))
					require.NoError(t, err)
					require.Len(t, haveRes, 1)

					have := haveRes[0]
					require.Empty(t, cmp.Diff(want.Policy, have.Policy,
						protocmp.Transform(), protocmp.IgnoreMessages(&policyv1.Metadata{})))
					require.NotNil(t, have.Metadata)
					require.Equal(t, namer.PolicyKeyFromFQN(want.FQN), have.Metadata.StoreIdentifier)
				})
			}
		})

		t.Run("list_policies", func(t *testing.T) {
			t.Run("should be able to list policies", func(t *testing.T) {
				have, err := store.ListPolicyIDs(ctx, storage.ListPolicyIDsParams{})
				require.NoError(t, err)
				require.Len(t, have, len(policyList))

				want := make([]string, len(policyList))
				for i, p := range policyList {
					want[i] = namer.PolicyKeyFromFQN(p.FQN)
				}

				require.ElementsMatch(t, want, have)
			})
		})

		t.Run("inspect_policies", func(t *testing.T) {
			t.Run("list of actions should match", func(t *testing.T) {
				results, err := store.InspectPolicies(ctx, storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err)

				for fqn, have := range results {
					expected := policy.ListActions(policyMap[fqn].Policy)
					require.ElementsMatch(t, expected, have.Actions)
				}
			})
		})

		t.Run("filter_policies", func(t *testing.T) {
			testCases := []struct {
				name   string
				params storage.ListPolicyIDsParams
			}{
				{
					name: "name regexp",
					params: storage.ListPolicyIDsParams{
						IncludeDisabled: true,
						NameRegexp:      ".*(leave|equipment)_[rw]equest$",
					},
				},
				{
					name: "scope regexp",
					params: storage.ListPolicyIDsParams{
						IncludeDisabled: true,
						ScopeRegexp:     "^acme",
					},
				},
				{
					name: "version regexp",
					params: storage.ListPolicyIDsParams{
						IncludeDisabled: true,
						VersionRegexp:   "default$",
					},
				},
				{
					name: "all regexp",
					params: storage.ListPolicyIDsParams{
						IncludeDisabled: true,
						NameRegexp:      ".*(leave|equipment)_[rw]equest$",
						ScopeRegexp:     "^acme",
						VersionRegexp:   "default$",
					},
				},
				{
					name: "policy ids",
					params: storage.ListPolicyIDsParams{
						IDs: []string{
							"resource.leave_request.vdefault",
						},
					},
				},
			}

			for _, tc := range testCases {
				tc := tc
				t.Run("should be able to filter policies "+tc.name, func(t *testing.T) {
					have, err := store.ListPolicyIDs(ctx, tc.params)
					require.NoError(t, err)
					filteredPolicyList := test.FilterPolicies(t, policyList, tc.params)
					require.Greater(t, len(filteredPolicyList), 0)
					require.Len(t, have, len(filteredPolicyList))

					want := make([]string, len(filteredPolicyList))
					for i, p := range filteredPolicyList {
						want[i] = namer.PolicyKeyFromFQN(p.FQN)
					}

					require.ElementsMatch(t, want, have)
				})
			}
		})

		t.Run("delete", func(t *testing.T) {
			checkEvents := storage.TestSubscription(store)

			err := store.Delete(ctx, rpx.ID)
			require.NoError(t, err)

			have, err := store.GetCompilationUnits(ctx, rpx.ID)
			require.NoError(t, err)
			require.Empty(t, have)

			checkEvents(t, timeout, storage.Event{Kind: storage.EventDeleteOrDisablePolicy, PolicyID: rpx.ID})
		})

		t.Run("add_schema", func(t *testing.T) {
			checkEvents := storage.TestSubscription(store)
			require.NoError(t, store.AddOrUpdateSchema(ctx, &schemav1.Schema{Id: schID, Definition: sch}))

			checkEvents(t, timeout, storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, schID))

			stats := store.RepoStats(ctx)
			require.Equal(t, 1, stats.SchemaCount)
		})

		t.Run("get_schema", func(t *testing.T) {
			t.Run("should be able to get schema", func(t *testing.T) {
				schema, err := store.LoadSchema(ctx, schID)
				require.NoError(t, err)
				require.NotEmpty(t, schema)
				schBytes, err := io.ReadAll(schema)
				require.NoError(t, err)
				require.NotEmpty(t, schBytes)
				require.JSONEq(t, string(sch), string(schBytes))
			})
		})

		t.Run("delete_schema", func(t *testing.T) {
			checkEvents := storage.TestSubscription(store)

			deletedSchemas, err := store.DeleteSchema(ctx, schID)
			require.NoError(t, err)
			require.Equal(t, uint32(1), deletedSchemas)

			have, err := store.LoadSchema(ctx, schID)
			require.Error(t, err)
			require.Empty(t, have)

			checkEvents(t, timeout, storage.NewSchemaEvent(storage.EventDeleteSchema, schID))
		})
	}
}

func withScope(p *policyv1.Policy, scope string) policy.Wrapper {
	//nolint:exhaustive
	switch policy.GetKind(p) {
	case policy.PrincipalKind:
		p.GetPrincipalPolicy().Scope = scope
	case policy.ResourceKind:
		p.GetResourcePolicy().Scope = scope
	}
	return policy.Wrap(p)
}

func TestCheckSchema(ctx context.Context, t *testing.T, s storage.Verifiable) {
	t.Helper()

	err := s.CheckSchema(ctx)
	require.NoError(t, err, "failed to check schema for the database storage")
}

func requireCompilationUnits(t *testing.T, want map[policy.Wrapper][]policy.Wrapper, have map[namer.ModuleID]*policy.CompilationUnit) {
	t.Helper()

	require.Len(t, have, len(want))
	for wantUnit, wantDefinitions := range want {
		require.Contains(t, have, wantUnit.ID)
		requireCompilationUnit(t, wantUnit.ID, wantDefinitions, have[wantUnit.ID])
	}
}

func requireCompilationUnit(t *testing.T, wantModID namer.ModuleID, wantDefinitions []policy.Wrapper, have *policy.CompilationUnit) {
	t.Helper()

	require.NotNil(t, have)
	require.Equal(t, wantModID, have.ModID)
	require.Len(t, have.Definitions, len(wantDefinitions))
	for _, wantDefinition := range wantDefinitions {
		require.Contains(t, have.Definitions, wantDefinition.ID)
		require.Empty(t, cmp.Diff(wantDefinition, have.Definitions[wantDefinition.ID], protocmp.Transform(), protocmp.IgnoreFields(&policyv1.Policy{}, "metadata")))
	}
}
