// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/inspect"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
)

func TestInspect(t *testing.T) {
	testCases := []struct {
		testFile              string
		expectedForPolicies   map[string]*responsev1.InspectPoliciesResponse_Result
		expectedForPolicySets map[string]*responsev1.InspectPoliciesResponse_Result
	}{
		{
			testFile: "all_types.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": {
					Variables: variables(
						variable(
							"derivedRoleVariable",
							"R.attr.isDerivedRoleVar",
							source(
								"derived_roles.common_roles",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
				"export_variables.common_variables": {
					Variables: variables(
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
					),
				},
				"principal.john.vdefault": {
					Actions: actions("*"),
					Variables: variables(
						variable(
							"label",
							"\"dude\"",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"teams",
							"[\"red\", \"blue\"]",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
				"resource.leave_request.vdefault": {
					Actions: actions("*", "create", "duplicate", "view"),
					Variables: variables(
						variable(
							"label",
							"\"dude\"",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"teams",
							"[\"red\", \"blue\"]",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": {
					Actions: actions("*"),
					Variables: variables(
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
					),
				},
				"resource.leave_request.vdefault": {
					Actions: actions("*", "create", "duplicate", "view"),
					Variables: variables(
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
						variable(
							"derivedRoleVariable",
							"R.attr.isDerivedRoleVar",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
					),
				},
			},
		},
		{
			testFile: "empty_actions.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": {
					Variables: variables(
						variable(
							"derivedRoleVariable",
							"R.attr.isDerivedRoleVar",
							source(
								"derived_roles.common_roles",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
					),
				},
				"export_variables.common_variables": {
					Variables: variables(
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
					),
				},
				"principal.john.vdefault": {
					Variables: variables(
						variable(
							"label",
							"\"dude\"",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"teams",
							"[\"red\", \"blue\"]",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
				"resource.leave_request.vdefault": {
					Variables: variables(
						variable(
							"label",
							"\"dude\"",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"teams",
							"[\"red\", \"blue\"]",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{},
		},
		{
			testFile: "empty_variables.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles":        {},
				"export_variables.common_variables": {},
				"principal.john.vdefault": {
					Actions: actions("*"),
				},
				"resource.leave_request.vdefault": {
					Actions: actions("*", "create", "duplicate", "view"),
				},
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": {
					Actions: actions("*"),
				},
				"resource.leave_request.vdefault": {
					Actions: actions("*", "create", "duplicate", "view"),
				},
			},
		},
		{
			testFile: "resolve_later_dr.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": {
					Variables: variables(
						variable(
							"derivedRoleVariable",
							"R.attr.isDerivedRoleVar",
							source(
								"derived_roles.common_roles",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
				"export_variables.common_variables": {
					Variables: variables(
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
					),
				},
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{},
		},
		{
			testFile: "resolve_later_pp.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": {
					Variables: variables(
						variable(
							"derivedRoleVariable",
							"R.attr.isDerivedRoleVar",
							source(
								"derived_roles.common_roles",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
				"export_variables.common_variables": {
					Variables: variables(
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
					),
				},
				"principal.john.vdefault": {
					Actions: actions("*"),
					Variables: variables(
						variable(
							"label",
							"\"dude\"",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"teams",
							"[\"red\", \"blue\"]",
							source(
								"principal.john.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": {
					Actions: actions("*"),
					Variables: variables(
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
					),
				},
			},
		},
		{
			testFile: "resolve_later_rp.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": {
					Variables: variables(
						variable(
							"derivedRoleVariable",
							"R.attr.isDerivedRoleVar",
							source(
								"derived_roles.common_roles",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
				"export_variables.common_variables": {
					Variables: variables(
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
							),
						),
					),
				},
				"resource.leave_request.vdefault": {
					Actions: actions("*", "create", "duplicate", "view"),
					Variables: variables(
						variable(
							"label",
							"\"dude\"",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"teams",
							"[\"red\", \"blue\"]",
							source(
								"resource.leave_request.vdefault",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
							),
						),
						variable(
							"commonLabel",
							"\"dude\"",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"commonTeams",
							"[\"red\", \"blue\"]",
							source(
								"export_variables.common_variables",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
					),
				},
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"resource.leave_request.vdefault": {
					Actions: actions("*", "create", "duplicate", "view"),
					Variables: variables(
						variable(
							"commonMarkedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
						variable(
							"derivedRoleVariable",
							"R.attr.isDerivedRoleVar",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
							),
						),
						variable(
							"markedResource",
							"R.attr.markedResource",
							source(
								"",
								responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
							),
						),
					),
				},
			},
		},
	}

	ctx := context.Background()
	for _, testCase := range testCases {
		idx, err := index.Build(ctx, test.ExtractTxtArchiveToFS(t, filepath.Join("testdata", testCase.testFile)))
		require.NoError(t, err, testCase.testFile)

		policyIDs, err := idx.ListPolicyIDs(ctx)
		require.NoError(t, err)

		t.Run(testCase.testFile, func(t *testing.T) {
			t.Run("Policies", func(t *testing.T) {
				ins := inspect.Policies()
				for _, policyID := range policyIDs {
					policies, err := idx.LoadPolicy(ctx, policyID)
					require.NoError(t, err)
					require.NotEmpty(t, policies)

					ins.Inspect(policies[0].Policy)
				}

				have, err := ins.Results()
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(testCase.expectedForPolicies, have, protocmp.Transform()))
			})

			t.Run("PolicySets", func(t *testing.T) {
				mgr := schema.NewNopManager()
				ins := inspect.PolicySets()
				for unit := range idx.GetAllCompilationUnits(ctx) {
					rps, err := compile.Compile(unit, mgr)
					require.NoError(t, err)
					ins.Inspect(rps)
				}

				have, err := ins.Results()
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(testCase.expectedForPolicySets, have, protocmp.Transform()))
			})
		})
	}
}

func actions(actions ...string) []string {
	return actions
}

func variable(name, value string, source *responsev1.InspectPoliciesResponse_Variable_Source) *responsev1.InspectPoliciesResponse_Variable {
	return &responsev1.InspectPoliciesResponse_Variable{
		Name:   name,
		Value:  value,
		Source: source,
	}
}

func variables(variables ...*responsev1.InspectPoliciesResponse_Variable) []*responsev1.InspectPoliciesResponse_Variable {
	return variables
}

func source(policyKey string, t responsev1.InspectPoliciesResponse_Variable_Source_Type) *responsev1.InspectPoliciesResponse_Variable_Source {
	if policyKey == "" {
		return &responsev1.InspectPoliciesResponse_Variable_Source{
			Type: t,
		}
	}

	return &responsev1.InspectPoliciesResponse_Variable_Source{
		Type: t,
		Id:   policyKey,
	}
}
