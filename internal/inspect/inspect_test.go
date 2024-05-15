// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/inspect"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestInspect(t *testing.T) {
	type policies struct {
		expected               map[string]*responsev1.InspectPoliciesResponse_Result
		expectedErr            string
		expectedMissingImports []string
	}
	type policySets struct {
		expected         map[string]*responsev1.InspectPoliciesResponse_Result
		expectedIndexErr bool
		skip             bool
	}
	testCases := []struct {
		testFile   string
		policies   policies
		policySets policySets
	}{
		{
			testFile: "empty.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{},
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{},
			},
		},
		{
			testFile: "empty_actions.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{},
			},
		},
		{
			testFile: "empty_variables.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
		},
		{
			testFile: "missing_imports.txt",
			policies: policies{
				expected:               map[string]*responsev1.InspectPoliciesResponse_Result{},
				expectedErr:            "failed to find imported policy export_variables.common_variables in the inspected policies",
				expectedMissingImports: []string{"export_variables.common_variables"},
			},
			policySets: policySets{
				expected:         map[string]*responsev1.InspectPoliciesResponse_Result{},
				expectedIndexErr: true,
			},
		},
		{
			testFile: "multiple_refs.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
		},
		{
			testFile: "reverse_order_dr.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{},
			},
		},
		{
			testFile: "reverse_order_pp.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"principal.john.vdefault": result(
						actions("*"),
						variables(
							variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						),
					),
				},
			},
		},
		{
			testFile: "reverse_order_rp.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"resource.leave_request.vdefault": result(
						actions("*", "create", "duplicate", "view"),
						variables(
							variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						),
					),
				},
			},
		},
		{
			testFile: "two_of_each_policy.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
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
		},
		{
			testFile: "undefined_variable.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"export_variables.common_variables": result(
						nil,
						variables(
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						),
					),
					"resource.leave_request.vdefault": result(
						actions("approve"),
						variables(
							variable("commonLabel", "null", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNDEFINED, true),
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						),
					),
				},
			},
			policySets: policySets{
				skip: true,
			},
		},
		{
			testFile: "undefined_variable_no_imports.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"resource.leave_request.vdefault": result(
						actions("approve"),
						variables(
							variable("commonLabel", "null", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNDEFINED, true),
						),
					),
				},
			},
			policySets: policySets{
				skip: true,
			},
		},
	}

	ctx := context.Background()
	for _, testCase := range testCases {
		t.Run(testCase.testFile, func(t *testing.T) {
			t.Run("Policies", func(t *testing.T) {
				dir := t.TempDir()
				test.ExtractTxtArchiveToDir(t, filepath.Join("testdata", testCase.testFile), dir)
				files := walkDir(t, dir)

				policyIDs := make([]string, 0, len(files))
				for f := range files {
					policyIDs = append(policyIDs, f)
				}

				ins := inspect.Policies()
				for _, policyID := range policyIDs {
					b, ok := files[policyID]
					require.True(t, ok, "policy does not exist")

					p, err := policy.ReadPolicy(bytes.NewReader(b))
					require.NoError(t, err)
					require.NoError(t, ins.Inspect(p))
				}

				have, err := ins.Results()
				if testCase.policies.expectedErr != "" {
					require.ErrorContains(t, err, testCase.policies.expectedErr)
					if len(testCase.policies.expectedMissingImports) > 0 {
						require.ElementsMatch(t, testCase.policies.expectedMissingImports, ins.MissingImports())
					}
				} else {
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(testCase.policies.expected, have, protocmp.Transform()))
				}
			})

			t.Run("PolicySets", func(t *testing.T) {
				if testCase.policySets.skip {
					t.Skip()
				}

				idx, err := index.Build(ctx, test.ExtractTxtArchiveToFS(t, filepath.Join("testdata", testCase.testFile)))
				if testCase.policySets.expectedIndexErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

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
				require.Empty(t, cmp.Diff(testCase.policySets.expected, have, protocmp.Transform()))
			})
		})
	}
}

func walkDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()

	fsys := os.DirFS(dir)
	files := make(map[string][]byte)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)

		if d.IsDir() {
			return nil
		}

		if _, ok := util.IsSupportedFileTypeExt(d.Name()); !ok {
			t.Errorf("Unsupported file: %s", d.Name())
		}

		f, err := fs.ReadFile(fsys, path)
		require.NoError(t, err)

		files[path] = f
		return nil
	})
	require.NoError(t, err)

	return files
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
