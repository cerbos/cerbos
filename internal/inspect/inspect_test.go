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
			testFile:              "empty.txt",
			expectedForPolicies:   map[string]*responsev1.InspectPoliciesResponse_Result{},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{},
		},
		{
			testFile: "empty_actions.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": result(
					nil,
					variables(
						variable("someVar", "\"someVar\"", "principal.john.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
					),
				),
				"resource.leave_request.vdefault": result(
					nil,
					variables(
						variable("someVar", "\"someVar\"", "resource.leave_request.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
					),
				),
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{},
		},
		{
			testFile: "empty_variables.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": result(
					actions("*"),
					nil,
				),
				"resource.leave_request.vdefault": result(
					actions("approve"),
					nil,
				),
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": result(
					actions("*"),
					nil,
				),
				"resource.leave_request.vdefault": result(
					actions("approve"),
					nil,
				),
			},
		},
		{
			testFile: "multiple_refs.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"export_variables.common_variables": result(
					nil,
					variables(
						variable("commonVar", "request.resource.attr.commonVar", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
					),
				),
				"principal.john.vdefault": result(
					actions("all", "any", "none"),
					variables(
						variable("commonVar", "request.resource.attr.commonVar", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("var", "request.resource.attr.var", "principal.john.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"resource.leave_request.vdefault": result(
					actions("all", "any", "none"),
					variables(
						variable("commonVar", "request.resource.attr.commonVar", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("var", "request.resource.attr.var", "resource.leave_request.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": result(
					actions("all", "any", "none"),
					variables(
						variable("commonVar", "request.resource.attr.commonVar", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("var", "request.resource.attr.var", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
				"resource.leave_request.vdefault": result(
					actions("all", "any", "none"),
					variables(
						variable("commonVar", "request.resource.attr.commonVar", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("var", "request.resource.attr.var", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
			},
		},
		{
			testFile: "reverse_order_dr.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": result(
					nil,
					variables(
						variable("commonTeams", "[\"red\", \"blue\"]", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("derivedRoleVariable", "R.attr.isDerivedRoleVar", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"export_variables.common_variables": result(
					nil,
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						variable("commonTeams", "[\"red\", \"blue\"]", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
					),
				),
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{},
		},
		{
			testFile: "reverse_order_pp.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": result(
					nil,
					variables(
						variable("derivedRoleVariable", "R.attr.isDerivedRoleVar", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"export_variables.common_variables": result(
					nil,
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						variable("commonTeams", "[\"red\", \"blue\"]", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
					),
				),
				"principal.john.vdefault": result(
					actions("*"),
					variables(
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("label", "\"dude\"", "principal.john.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
						variable("markedResource", "R.attr.markedResource", "principal.john.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						variable("teams", "[\"red\", \"blue\"]", "principal.john.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
					),
				),
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john.vdefault": result(
					actions("*"),
					variables(
						variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
			},
		},
		{
			testFile: "reverse_order_rp.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles": result(
					nil,
					variables(
						variable("derivedRoleVariable", "R.attr.isDerivedRoleVar", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"export_variables.common_variables": result(
					nil,
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						variable("commonTeams", "[\"red\", \"blue\"]", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
					),
				),
				"resource.leave_request.vdefault": result(
					actions("*", "create", "duplicate", "view"),
					variables(
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("label", "\"dude\"", "resource.leave_request.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
						variable("markedResource", "R.attr.markedResource", "resource.leave_request.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						variable("teams", "[\"red\", \"blue\"]", "resource.leave_request.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
					),
				),
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"resource.leave_request.vdefault": result(
					actions("*", "create", "duplicate", "view"),
					variables(
						variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
			},
		},
		{
			testFile: "two_of_each_policy.txt",
			expectedForPolicies: map[string]*responsev1.InspectPoliciesResponse_Result{
				"derived_roles.common_roles_1": result(
					nil,
					variables(
						variable("derivedRoleVariable1", "R.attr.isDerivedRoleVar", "derived_roles.common_roles_1", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"derived_roles.common_roles_2": result(
					nil,
					variables(
						variable("derivedRoleVariable2", "R.attr.isDerivedRoleVar", "derived_roles.common_roles_2", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"export_variables.common_variables_1": result(
					nil,
					variables(
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
					),
				),
				"export_variables.common_variables_2": result(
					nil,
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
					),
				),
				"principal.john_1.vdefault": result(
					actions("*"),
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("markedResource", "R.attr.markedResource", "principal.john_1.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"principal.john_2.vdefault": result(
					actions("*"),
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("label", "\"dude\"", "principal.john_2.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"resource.leave_request_1.vdefault": result(
					actions("*", "create", "duplicate", "view"),
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("markedResource", "R.attr.markedResource", "resource.leave_request_1.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
				"resource.leave_request_2.vdefault": result(
					actions("*", "create", "duplicate"),
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("label", "\"dude\"", "resource.leave_request_2.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
			},
			expectedForPolicySets: map[string]*responsev1.InspectPoliciesResponse_Result{
				"principal.john_1.vdefault": result(
					actions("*"),
					variables(
						variable("commonLabel", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
				"principal.john_2.vdefault": result(
					actions("*"),
					variables(
						variable("commonLabel", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("label", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
				"resource.leave_request_1.vdefault": result(
					actions("*", "create", "duplicate", "view"),
					variables(
						variable("commonLabel", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
				"resource.leave_request_2.vdefault": result(
					actions("*", "create", "duplicate"),
					variables(
						variable("commonLabel", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						variable("label", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
					),
				),
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

					err = ins.Inspect(policies[0].Policy)
					require.NoError(t, err)
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

					if rps == nil {
						continue
					}

					err = ins.Inspect(rps)
					require.NoError(t, err)
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

func result(actions []string, variables []*responsev1.InspectPoliciesResponse_Variable) *responsev1.InspectPoliciesResponse_Result {
	return &responsev1.InspectPoliciesResponse_Result{
		Actions:   actions,
		Variables: variables,
	}
}

func variable(name, value, source string, kind responsev1.InspectPoliciesResponse_Variable_Kind, used bool) *responsev1.InspectPoliciesResponse_Variable {
	if source == "" {
		return &responsev1.InspectPoliciesResponse_Variable{
			Name:  name,
			Value: value,
			Kind:  kind,
			Used:  used,
		}
	}

	return &responsev1.InspectPoliciesResponse_Variable{
		Name:   name,
		Value:  value,
		Source: source,
		Kind:   kind,
		Used:   used,
	}
}

func variables(variables ...*responsev1.InspectPoliciesResponse_Variable) []*responsev1.InspectPoliciesResponse_Variable {
	return variables
}
