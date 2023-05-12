// Copyright 2021-2023 Zenauth Ltd.
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

//nolint:gomnd
func TestSuite(store DBStorage) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		pp := policy.Wrap(test.GenPrincipalPolicy(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))
		rpx := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("x", "x")))
		drx := policy.Wrap(test.GenDerivedRoles(test.PrefixAndSuffix("x", "x")))

		rpAcme := withScope(test.GenResourcePolicy(test.NoMod()), "acme")
		rpAcmeHR := withScope(test.GenResourcePolicy(test.NoMod()), "acme.hr")
		rpAcmeHRUK := withScope(test.GenResourcePolicy(test.NoMod()), "acme.hr.uk")
		ppAcme := withScope(test.GenPrincipalPolicy(test.NoMod()), "acme")
		ppAcmeHR := withScope(test.GenPrincipalPolicy(test.NoMod()), "acme.hr")

		policyList := []policy.Wrapper{rp, pp, dr, rpx, drx, rpAcme, rpAcmeHR, rpAcmeHRUK, ppAcme, ppAcmeHR}

		sch := test.ReadSchemaFromFile(t, test.PathToDir(t, "store/_schemas/resources/leave_request.json"))
		const schID = "leave_request"

		t.Run("add", func(t *testing.T) {
			checkEvents := storage.TestSubscription(store)
			require.NoError(t, store.AddOrUpdate(ctx, policyList...))

			wantEvents := []storage.Event{
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rp.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: pp.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: dr.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpx.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: drx.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpAcme.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpAcmeHR.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rpAcmeHRUK.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: ppAcme.ID},
				{Kind: storage.EventAddOrUpdatePolicy, PolicyID: ppAcmeHR.ID},
			}
			checkEvents(t, timeout, wantEvents...)

			stats := store.RepoStats(ctx)
			require.Equal(t, 5, stats.PolicyCount[policy.ResourceKind])
			require.Equal(t, 3, stats.PolicyCount[policy.PrincipalKind])
			require.Equal(t, 2, stats.PolicyCount[policy.DerivedRolesKind])
		})

		t.Run("get_compilation_unit_with_deps", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rp.ID)
			require.NoError(t, err)
			require.Len(t, have, 1)
			require.Contains(t, have, rp.ID)

			haveRec := have[rp.ID]
			require.Equal(t, rp.ID, haveRec.ModID)
			require.Len(t, haveRec.Definitions, 2)

			require.Contains(t, haveRec.Definitions, rp.ID)
			require.Empty(t, cmp.Diff(rp, haveRec.Definitions[rp.ID], protocmp.Transform()))

			require.Contains(t, haveRec.Definitions, dr.ID)
			require.Empty(t, cmp.Diff(dr, haveRec.Definitions[dr.ID], protocmp.Transform()))
		})

		t.Run("get_compilation_unit_without_deps", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, pp.ID)
			require.NoError(t, err)
			require.Len(t, have, 1)
			require.Contains(t, have, pp.ID)

			haveRec := have[pp.ID]
			require.Equal(t, pp.ID, haveRec.ModID)
			require.Len(t, haveRec.Definitions, 1)

			require.Contains(t, haveRec.Definitions, pp.ID)
			require.Empty(t, cmp.Diff(pp, haveRec.Definitions[pp.ID], protocmp.Transform()))
		})

		t.Run("get_compilation_unit_for_scoped_resource_policy", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rpAcmeHRUK.ID)
			require.NoError(t, err)
			require.Len(t, have, 1)
			require.Contains(t, have, rpAcmeHRUK.ID)

			haveRec := have[rpAcmeHRUK.ID]
			require.Equal(t, rpAcmeHRUK.ID, haveRec.ModID)
			require.Len(t, haveRec.Definitions, 5)
			require.Contains(t, haveRec.Definitions, rpAcmeHRUK.ID)
			require.Empty(t, cmp.Diff(rpAcmeHRUK, haveRec.Definitions[rpAcmeHRUK.ID], protocmp.Transform()))
			require.Contains(t, haveRec.Definitions, rpAcmeHR.ID)
			require.Empty(t, cmp.Diff(rpAcmeHR, haveRec.Definitions[rpAcmeHR.ID], protocmp.Transform()))
			require.Contains(t, haveRec.Definitions, rpAcme.ID)
			require.Empty(t, cmp.Diff(rpAcme, haveRec.Definitions[rpAcme.ID], protocmp.Transform()))
			require.Contains(t, haveRec.Definitions, rp.ID)
			require.Empty(t, cmp.Diff(rp, haveRec.Definitions[rp.ID], protocmp.Transform()))
			require.Contains(t, haveRec.Definitions, dr.ID)
			require.Empty(t, cmp.Diff(dr, haveRec.Definitions[dr.ID], protocmp.Transform()))
		})

		t.Run("get_compilation_unit_for_scoped_principal_policy", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, ppAcmeHR.ID)
			require.NoError(t, err)
			require.Len(t, have, 1)
			require.Contains(t, have, ppAcmeHR.ID)

			haveRec := have[ppAcmeHR.ID]
			require.Equal(t, ppAcmeHR.ID, haveRec.ModID)
			require.Len(t, haveRec.Definitions, 3)
			require.Contains(t, haveRec.Definitions, ppAcmeHR.ID)
			require.Empty(t, cmp.Diff(ppAcmeHR, haveRec.Definitions[ppAcmeHR.ID], protocmp.Transform()))
			require.Contains(t, haveRec.Definitions, ppAcme.ID)
			require.Empty(t, cmp.Diff(ppAcme, haveRec.Definitions[ppAcme.ID], protocmp.Transform()))
			require.Contains(t, haveRec.Definitions, pp.ID)
			require.Empty(t, cmp.Diff(pp, haveRec.Definitions[pp.ID], protocmp.Transform()))
		})

		t.Run("get_multiple_compilation_units", func(t *testing.T) {
			have, err := store.GetCompilationUnits(ctx, rp.ID, pp.ID, rpAcmeHRUK.ID)
			require.NoError(t, err)
			require.Len(t, have, 3)
			require.Contains(t, have, rp.ID)
			require.Contains(t, have, pp.ID)
			require.Contains(t, have, rpAcmeHRUK.ID)

			haveRP := have[rp.ID]
			require.Equal(t, rp.ID, haveRP.ModID)
			require.Len(t, haveRP.Definitions, 2)
			require.Contains(t, haveRP.Definitions, rp.ID)
			require.Empty(t, cmp.Diff(rp, haveRP.Definitions[rp.ID], protocmp.Transform()))
			require.Contains(t, haveRP.Definitions, dr.ID)
			require.Empty(t, cmp.Diff(dr, haveRP.Definitions[dr.ID], protocmp.Transform()))

			havePP := have[pp.ID]
			require.Equal(t, pp.ID, havePP.ModID)
			require.Len(t, havePP.Definitions, 1)
			require.Contains(t, havePP.Definitions, pp.ID)
			require.Empty(t, cmp.Diff(pp, havePP.Definitions[pp.ID], protocmp.Transform()))

			haveRPAcmeHRUK := have[rpAcmeHRUK.ID]
			require.Equal(t, rpAcmeHRUK.ID, haveRPAcmeHRUK.ModID)
			require.Len(t, haveRPAcmeHRUK.Definitions, 5)
			require.Contains(t, haveRPAcmeHRUK.Definitions, rpAcmeHRUK.ID)
			require.Empty(t, cmp.Diff(rpAcmeHRUK, haveRPAcmeHRUK.Definitions[rpAcmeHRUK.ID], protocmp.Transform()))
			require.Contains(t, haveRPAcmeHRUK.Definitions, rpAcmeHR.ID)
			require.Empty(t, cmp.Diff(rpAcmeHR, haveRPAcmeHRUK.Definitions[rpAcmeHR.ID], protocmp.Transform()))
			require.Contains(t, haveRPAcmeHRUK.Definitions, rpAcme.ID)
			require.Empty(t, cmp.Diff(rpAcme, haveRPAcmeHRUK.Definitions[rpAcme.ID], protocmp.Transform()))
			require.Contains(t, haveRPAcmeHRUK.Definitions, rp.ID)
			require.Empty(t, cmp.Diff(rp, haveRPAcmeHRUK.Definitions[rp.ID], protocmp.Transform()))
			require.Contains(t, haveRPAcmeHRUK.Definitions, dr.ID)
			require.Empty(t, cmp.Diff(dr, haveRPAcmeHRUK.Definitions[dr.ID], protocmp.Transform()))
		})

		t.Run("get_non_existent_compilation_unit", func(t *testing.T) {
			p := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("y", "y")))
			have, err := store.GetCompilationUnits(ctx, p.ID)
			require.NoError(t, err)
			require.Empty(t, have)
		})

		t.Run("get_dependents", func(t *testing.T) {
			have, err := store.GetDependents(ctx, dr.ID)
			require.NoError(t, err)

			require.Len(t, have, 1)
			require.Contains(t, have, dr.ID)

			haveDeps := have[dr.ID]
			require.Len(t, haveDeps, 4)
			require.Contains(t, haveDeps, rp.ID)
			require.Contains(t, haveDeps, rpAcme.ID)
			require.Contains(t, haveDeps, rpAcmeHR.ID)
			require.Contains(t, haveDeps, rpAcmeHRUK.ID)
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
				have, err := store.ListPolicyIDs(ctx, false)
				require.NoError(t, err)
				require.Len(t, have, len(policyList))

				want := make([]string, len(policyList))
				for i, p := range policyList {
					want[i] = namer.PolicyKeyFromFQN(p.FQN)
				}

				require.ElementsMatch(t, want, have)
			})
		})

		t.Run("delete", func(t *testing.T) {
			checkEvents := storage.TestSubscription(store)

			err := store.Delete(ctx, rpx.ID)
			require.NoError(t, err)

			have, err := store.GetCompilationUnits(ctx, rpx.ID)
			require.NoError(t, err)
			require.Empty(t, have)

			checkEvents(t, timeout, storage.Event{Kind: storage.EventDeletePolicy, PolicyID: rpx.ID})
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

func TestVerifiable(ctx context.Context, t *testing.T, s storage.Verifiable) {
	t.Helper()

	err := s.Verify(ctx)
	require.NoError(t, err, "failed to verify schema for the database storage")
}
