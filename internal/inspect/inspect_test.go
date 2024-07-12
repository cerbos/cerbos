// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect_test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/inspect"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestInspect(t *testing.T) {
	type policies struct {
		expected map[string]*responsev1.InspectPoliciesResponse_Result
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
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"derived_roles.common_roles": result(
						"a.yaml",
						nil,
						nil,
						derivedRoles(
							derivedRole(
								"approved_user",
								"derived_roles.common_roles",
								responsev1.InspectPoliciesResponse_DerivedRole_KIND_EXPORTED,
							),
						),
						nil,
					),
					"principal.john.vdefault":         result("c.yaml", nil, nil, nil, nil),
					"resource.leave_request.vdefault": result("d.yaml", nil, nil, nil, nil),
				},
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"principal.john.vdefault":         result("principal.john.vdefault", nil, nil, nil, nil),
					"resource.leave_request.vdefault": result("resource.leave_request.vdefault", nil, nil, nil, nil),
				},
			},
		},
		{
			testFile: "empty_actions.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"principal.john.vdefault": result(
						"a.yaml",
						nil,
						nil,
						nil,
						variables(
							variable("someVar", "\"someVar\"", "principal.john.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
						),
					),
					"resource.leave_request.vdefault": result(
						"b.yaml",
						nil,
						nil,
						nil,
						variables(
							variable("someVar", "\"someVar\"", "resource.leave_request.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, false),
						),
					),
				},
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"principal.john.vdefault":         result("principal.john.vdefault", nil, nil, nil, nil),
					"resource.leave_request.vdefault": result("resource.leave_request.vdefault", nil, nil, nil, nil),
				},
			},
		},
		{
			testFile: "empty_variables.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"principal.john.vdefault": result(
						"a.yaml",
						actions("*"),
						attributes(
							attribute("someAttr", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						nil,
					),
					"resource.leave_request.vdefault": result(
						"b.yaml",
						actions("approve"),
						nil,
						nil,
						nil,
					),
				},
			},
			policySets: policySets{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"principal.john.vdefault": result(
						"principal.john.vdefault",
						actions("*"),
						attributes(
							attribute("someAttr", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						nil,
					),
					"resource.leave_request.vdefault": result(
						"resource.leave_request.vdefault",
						actions("approve"),
						nil,
						nil,
						nil,
					),
				},
			},
		},
		{
			testFile: "multiple_refs.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"export_variables.common_variables": result(
						"a.yaml",
						nil,
						attributes(
							attribute("commonVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonVar", "request.resource.attr.commonVar", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						),
					),
					"principal.john.vdefault": result(
						"c.yaml",
						actions("all", "any", "none"),
						attributes(
							attribute("commonVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("var", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonVar", "request.resource.attr.commonVar", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("var", "request.resource.attr.var", "principal.john.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"resource.leave_request.vdefault": result(
						"b.yaml",
						actions("all", "any", "none"),
						attributes(
							attribute("commonVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("var", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
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
						"principal.john.vdefault",
						actions("all", "any", "none"),
						attributes(
							attribute("commonVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("var", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonVar", "request.resource.attr.commonVar", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("var", "request.resource.attr.var", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						),
					),
					"resource.leave_request.vdefault": result(
						"resource.leave_request.vdefault",
						actions("all", "any", "none"),
						attributes(
							attribute("commonVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("var", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
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
						"a.yaml",
						nil,
						attributes(
							attribute("isDerivedRoleVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_PRINCIPAL_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_DerivedRole_KIND_EXPORTED),
						),
						variables(
							variable("commonTeams", "[\"red\", \"blue\"]", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("derivedRoleVariable", "P.attr.isDerivedRoleVar", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"export_variables.common_variables": result(
						"b.yaml",
						nil,
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
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
						"c.yaml",
						nil,
						attributes(
							attribute("isDerivedRoleVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_DerivedRole_KIND_EXPORTED),
						),
						variables(
							variable("derivedRoleVariable", "R.attr.isDerivedRoleVar", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"export_variables.common_variables": result(
						"b.yaml",
						nil,
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonLabel", "\"dude\"", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
							variable("commonTeams", "[\"red\", \"blue\"]", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						),
					),
					"principal.john.vdefault": result(
						"a.yaml",
						actions("*"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
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
						"principal.john.vdefault",
						actions("*"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
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
						"c.yaml",
						nil,
						attributes(
							attribute("isDerivedRoleVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_DerivedRole_KIND_EXPORTED),
						),
						variables(
							variable("derivedRoleVariable", "R.attr.isDerivedRoleVar", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"export_variables.common_variables": result(
						"b.yaml",
						nil,
						attributes(
							attribute("commonMarkedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonLabel", "\"dude\"", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
							variable("commonMarkedResource", "R.attr.commonMarkedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
							variable("commonTeams", "[\"red\", \"blue\"]", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						),
					),
					"resource.leave_request.vdefault": result(
						"a.yaml",
						actions("*", "create", "duplicate", "view"),
						attributes(
							attribute("approvedUser", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("commonMarkedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("someAttr", responsev1.InspectPoliciesResponse_Attribute_TYPE_PRINCIPAL_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user", "derived_roles.common_roles", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
						),
						variables(
							variable("commonMarkedResource", "R.attr.commonMarkedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
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
						"resource.leave_request.vdefault",
						actions("*", "create", "duplicate", "view"),
						attributes(
							attribute("approvedUser", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("commonMarkedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
							attribute("someAttr", responsev1.InspectPoliciesResponse_Attribute_TYPE_PRINCIPAL_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user", "", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
						),
						variables(
							variable("commonMarkedResource", "R.attr.commonMarkedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
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
						"c.yaml",
						nil,
						attributes(
							attribute("isDerivedRoleVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user_1", "derived_roles.common_roles_1", responsev1.InspectPoliciesResponse_DerivedRole_KIND_EXPORTED),
						),
						variables(
							variable("derivedRoleVariable1", "R.attr.isDerivedRoleVar", "derived_roles.common_roles_1", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"derived_roles.common_roles_2": result(
						"d.yaml",
						nil,
						attributes(
							attribute("isDerivedRoleVar", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user_2", "derived_roles.common_roles_2", responsev1.InspectPoliciesResponse_DerivedRole_KIND_EXPORTED),
						),
						variables(
							variable("derivedRoleVariable2", "R.attr.isDerivedRoleVar", "derived_roles.common_roles_2", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"export_variables.common_variables_1": result(
						"a.yaml",
						nil,
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						),
					),
					"export_variables.common_variables_2": result(
						"b.yaml",
						nil,
						nil,
						nil,
						variables(
							variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						),
					),
					"principal.john_1.vdefault": result(
						"e.yaml",
						actions("*"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("markedResource", "R.attr.markedResource", "principal.john_1.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"principal.john_2.vdefault": result(
						"f.yaml",
						actions("*"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("label", "\"dude\"", "principal.john_2.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"resource.leave_request_1.vdefault": result(
						"g.yaml",
						actions("*", "create", "duplicate", "view"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user_1", "derived_roles.common_roles_1", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
							derivedRole("approved_user_2", "derived_roles.common_roles_2", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
						),
						variables(
							variable("commonLabel", "\"dude\"", "export_variables.common_variables_2", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables_1", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("markedResource", "R.attr.markedResource", "resource.leave_request_1.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
						),
					),
					"resource.leave_request_2.vdefault": result(
						"h.yaml",
						actions("*", "create", "duplicate"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user_1", "derived_roles.common_roles_1", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
							derivedRole("approved_user_2", "derived_roles.common_roles_2", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
						),
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
						"principal.john_1.vdefault",
						actions("*"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonLabel", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						),
					),
					"principal.john_2.vdefault": result(
						"principal.john_2.vdefault",
						actions("*"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonLabel", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("label", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						),
					),
					"resource.leave_request_1.vdefault": result(
						"resource.leave_request_1.vdefault",
						actions("*", "create", "duplicate", "view"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user_1", "", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
							derivedRole("approved_user_2", "", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
						),
						variables(
							variable("commonLabel", "\"dude\"", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("commonMarkedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
							variable("markedResource", "R.attr.markedResource", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN, true),
						),
					),
					"resource.leave_request_2.vdefault": result(
						"resource.leave_request_2.vdefault",
						actions("*", "create", "duplicate"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						derivedRoles(
							derivedRole("approved_user_1", "", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
							derivedRole("approved_user_2", "", responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED),
						),
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
			testFile: "undefined_derived_role.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"resource.leave_request.vdefault": result(
						"a.yaml",
						actions("approve"),
						nil,
						derivedRoles(
							derivedRole("undefined_derived_role", "", responsev1.InspectPoliciesResponse_DerivedRole_KIND_UNDEFINED),
						),
						nil,
					),
				},
			},
			policySets: policySets{
				skip: true,
			},
		},
		{
			testFile: "undefined_variable.txt",
			policies: policies{
				expected: map[string]*responsev1.InspectPoliciesResponse_Result{
					"export_variables.common_variables": result(
						"b.yaml",
						nil,
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED, false),
						),
					),
					"resource.leave_request.vdefault": result(
						"a.yaml",
						actions("approve"),
						attributes(
							attribute("markedResource", responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE),
						),
						nil,
						variables(
							variable("commonMarkedResource", "R.attr.markedResource", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
							variable("missingVar", "null", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNDEFINED, true),
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
						"a.yaml",
						actions("approve"),
						nil,
						nil,
						variables(
							variable("missingVar", "null", "", responsev1.InspectPoliciesResponse_Variable_KIND_UNDEFINED, true),
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
		pathToTestFile := filepath.Join("testdata", "cases", testCase.testFile)
		t.Run(testCase.testFile, func(t *testing.T) {
			t.Run("Policies", func(t *testing.T) {
				pl := mkPolicyLoader(t, filepath.Join("testdata", "cases", testCase.testFile))
				dir := t.TempDir()
				test.ExtractTxtArchiveToDir(t, pathToTestFile, dir)
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

				have, err := ins.Results(ctx, pl.LoadPolicy)
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(testCase.policies.expected, have, protocmp.Transform()))
			})

			t.Run("PolicySets", func(t *testing.T) {
				if testCase.policySets.skip {
					t.Skip()
				}

				idx, err := index.Build(ctx, test.ExtractTxtArchiveToFS(t, pathToTestFile))
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

func TestInspectMissingImport(t *testing.T) {
	testCases := []struct {
		testFile               string
		expected               map[string]*responsev1.InspectPoliciesResponse_Result
		expectedMissingImports []string
	}{
		{
			testFile: "missing_imports.txt",
			expected: map[string]*responsev1.InspectPoliciesResponse_Result{
				"resource.leave_request.vdefault": result(
					"a.yaml",
					actions("approve"),
					nil,
					nil,
					variables(
						variable("commonLabel", "\"dude\"", "export_variables.common_variables", responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED, true),
						variable("label", "\"dude\"", "resource.leave_request.vdefault", responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL, true),
					),
				),
			},
			expectedMissingImports: []string{"export_variables.common_variables"},
		},
	}

	ctx := context.Background()
	for _, testCase := range testCases {
		t.Run(testCase.testFile, func(t *testing.T) {
			pathToTestFile := filepath.Join("testdata", "cases", testCase.testFile)
			pl := mkPolicyLoader(t, filepath.Join("testdata", "missing_policies.txt"))
			dir := t.TempDir()
			test.ExtractTxtArchiveToDir(t, pathToTestFile, dir)
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

			have, err := ins.Results(ctx, pl.LoadPolicy)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(testCase.expected, have, protocmp.Transform()))
			require.ElementsMatch(t, pl.loaded, testCase.expectedMissingImports)
		})
	}
}

func mkPolicyLoader(t *testing.T, path string) *policyLoader {
	t.Helper()

	fsys := test.ExtractTxtArchiveToFS(t, path)
	policies := make(map[string]*policyv1.Policy)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if _, ok := util.IsSupportedFileTypeExt(d.Name()); !ok {
			return fmt.Errorf("unsupported file type %s", d.Name())
		}

		f, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		p, err := policy.ReadPolicy(bytes.NewReader(f))
		if err != nil {
			return fmt.Errorf("failed to read policy: %w", err)
		}

		policies[namer.PolicyKey(p)] = p
		return nil
	})
	require.NoError(t, err)

	return &policyLoader{
		policies: policies,
	}
}

type policyLoader struct {
	policies map[string]*policyv1.Policy
	loaded   []string
}

func (pl *policyLoader) LoadPolicy(_ context.Context, policyKey ...string) ([]*policy.Wrapper, error) {
	policies := make([]*policy.Wrapper, 0, len(policyKey))
	for _, pk := range policyKey {
		p, ok := pl.policies[pk]
		if !ok {
			return nil, fmt.Errorf("failed to find policy with key %s", pk)
		}

		wp := policy.Wrap(p)
		policies = append(policies, &wp)
		pl.loaded = append(pl.loaded, pk)
	}

	return policies, nil
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

func result(policyID string, actions []string, attributes []*responsev1.InspectPoliciesResponse_Attribute, derivedRoles []*responsev1.InspectPoliciesResponse_DerivedRole, variables []*responsev1.InspectPoliciesResponse_Variable) *responsev1.InspectPoliciesResponse_Result {
	return &responsev1.InspectPoliciesResponse_Result{
		Actions:      actions,
		Attributes:   attributes,
		DerivedRoles: derivedRoles,
		PolicyId:     policyID,
		Variables:    variables,
	}
}

func actions(actions ...string) []string {
	return actions
}

func attribute(name string, t responsev1.InspectPoliciesResponse_Attribute_Type) *responsev1.InspectPoliciesResponse_Attribute {
	return &responsev1.InspectPoliciesResponse_Attribute{
		Name: name,
		Type: t,
	}
}

func attributes(attributes ...*responsev1.InspectPoliciesResponse_Attribute) []*responsev1.InspectPoliciesResponse_Attribute {
	return attributes
}

func derivedRole(name, source string, kind responsev1.InspectPoliciesResponse_DerivedRole_Kind) *responsev1.InspectPoliciesResponse_DerivedRole {
	return &responsev1.InspectPoliciesResponse_DerivedRole{
		Name:   name,
		Kind:   kind,
		Source: source,
	}
}

func derivedRoles(derivedRoles ...*responsev1.InspectPoliciesResponse_DerivedRole) []*responsev1.InspectPoliciesResponse_DerivedRole {
	return derivedRoles
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
