// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package policy_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	derivedRolesFmt = "derived_roles.my_derived_roles_%d"
	source          = "testsource"
)

var policyKey = fmt.Sprintf(derivedRolesFmt, 1)

func TestWith(t *testing.T) {
	t.Run("WithStoreIdentifier", func(t *testing.T) {
		p := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p.Metadata)

		p = policy.WithStoreIdentifier(p, policyKey)
		require.NotEmpty(t, p.Metadata.StoreIdentifier)
		require.Equal(t, fmt.Sprintf(derivedRolesFmt, 1), policyKey)
	})

	t.Run("WithHash", func(t *testing.T) {
		p1 := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p1.Metadata)

		p2 := policy.WithHash(p1)
		require.NotEmpty(t, p2.Metadata.Hash)
		require.Equal(t, wrapperspb.UInt64(util.HashPB(p2, policy.IgnoreHashFields)), p2.Metadata.Hash)

		p3 := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		p3.Description = "With additional fields set that don't affect the hash"
		p3.Disabled = true
		p3.JsonSchema = "https://api.cerbos.dev/latest/cerbos/policy/v1/Policy.schema.json"
		require.Equal(t, p2.Metadata.Hash, policy.WithHash(p3).Metadata.Hash)
	})

	t.Run("WithMetadata", func(t *testing.T) {
		p := test.GenDerivedRoles(test.Suffix(strconv.Itoa(1)))
		require.Empty(t, p.Metadata)

		keyVal := "test"
		p = policy.WithMetadata(p, source, map[string]string{keyVal: keyVal}, policyKey, policy.SourceFile(source))
		require.NotEmpty(t, p.Metadata)
		require.Equal(t, fmt.Sprintf(derivedRolesFmt, 1), policyKey)
		require.Equal(t, wrapperspb.UInt64(util.HashPB(p, policy.IgnoreHashFields)), p.Metadata.Hash)
		require.Equal(t, source, p.Metadata.SourceFile)
		require.Equal(t, keyVal, p.Metadata.Annotations[keyVal])
		require.Equal(t, source, p.Metadata.SourceAttributes.Attributes["source"].GetStringValue())
	})
}

func TestAncestors(t *testing.T) {
	testCases := []struct {
		scope string
		want  []namer.ModuleID
	}{
		{
			scope: "",
			want:  nil,
		},
		{
			scope: "foo",
			want: []namer.ModuleID{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"),
			},
		},
		{
			scope: "foo.bar",
			want: []namer.ModuleID{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"),
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"),
			},
		},
		{
			scope: "foo.bar.baz",
			want: []namer.ModuleID{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo.bar"),
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"),
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("scope=%q", tc.scope), func(t *testing.T) {
			p := test.GenResourcePolicy(test.NoMod())
			p.GetResourcePolicy().Scope = tc.scope
			have := policy.Ancestors(p)
			require.Equal(t, tc.want, have)
		})
	}
}

func TestRequiredAncestors(t *testing.T) {
	testCases := []struct {
		scope string
		want  map[namer.ModuleID]string
	}{
		{
			scope: "",
			want:  nil,
		},
		{
			scope: "foo",
			want: map[namer.ModuleID]string{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"): "cerbos.resource.leave_request.vdefault",
			},
		},
		{
			scope: "foo.bar",
			want: map[namer.ModuleID]string{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"): "cerbos.resource.leave_request.vdefault/foo",
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"):     "cerbos.resource.leave_request.vdefault",
			},
		},
		{
			scope: "foo.bar.baz",
			want: map[namer.ModuleID]string{
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo.bar"): "cerbos.resource.leave_request.vdefault/foo.bar",
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault/foo"):     "cerbos.resource.leave_request.vdefault/foo",
				namer.GenModuleIDFromFQN("cerbos.resource.leave_request.vdefault"):         "cerbos.resource.leave_request.vdefault",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("scope=%q", tc.scope), func(t *testing.T) {
			p := test.GenResourcePolicy(test.NoMod())
			p.GetResourcePolicy().Scope = tc.scope
			have := policy.RequiredAncestors(p)
			require.Equal(t, tc.want, have)
		})
	}
}

func TestInspectUtilities(t *testing.T) {
	dr := test.GenDerivedRoles(test.NoMod())
	ev := test.GenExportVariables(test.NoMod())
	rp := test.NewResourcePolicyBuilder("leave_request", "default").
		WithRules(
			test.
				NewResourceRule("a", "b").
				WithRoles("user").
				WithMatchExpr("V.geography").
				Build(),
			test.
				NewResourceRule("a").
				WithRoles("admin").
				Build(),
		).
		WithLocalVariable("geography", "request.resource.attr.geography").
		Build()
	pp := test.NewPrincipalPolicyBuilder("john", "default").
		WithRules(
			test.NewPrincipalRuleBuilder("leave_request").
				AllowActionWhenMatch("a", "V.geography").
				AllowAction("b").
				DenyAction("c").
				Build(),
			test.NewPrincipalRuleBuilder("purchase_order").
				AllowAction("a").
				DenyAction("c").
				Build(),
		).
		WithLocalVariable("geography", "request.resource.attr.geography").
		Build()

	drSet := compilePolicy(t, dr)
	evSet := compilePolicy(t, ev)
	rpSet := compilePolicy(t, rp)
	ppSet := compilePolicy(t, pp)

	t.Run("Actions", func(t *testing.T) {
		testCases := []struct {
			p               *policyv1.Policy
			pset            *runtimev1.RunnablePolicySet
			expectedActions []string
		}{
			{
				p:               dr,
				pset:            drSet,
				expectedActions: []string{},
			},
			{
				p:               ev,
				pset:            evSet,
				expectedActions: []string{},
			},
			{
				p:               rp,
				pset:            rpSet,
				expectedActions: []string{"a", "b"},
			},
			{
				p:               pp,
				pset:            ppSet,
				expectedActions: []string{"a", "b", "c"},
			},
		}

		t.Run("ListActions", func(t *testing.T) {
			for _, testCase := range testCases {
				haveActions := policy.ListActions(testCase.p)
				require.ElementsMatch(t, testCase.expectedActions, haveActions)
			}
		})

		t.Run("ListPolicySetActions", func(t *testing.T) {
			for _, testCase := range testCases {
				haveActions := policy.ListPolicySetActions(testCase.pset)
				require.ElementsMatch(t, testCase.expectedActions, haveActions)
			}
		})
	})

	t.Run("Variables", func(t *testing.T) {
		t.Run("ListVariables", func(t *testing.T) {
			testCases := []struct {
				p                 *policyv1.Policy
				pset              *runtimev1.RunnablePolicySet
				expectedVariables []*responsev1.InspectPoliciesResponse_Variable
			}{
				{
					p:    dr,
					pset: compilePolicy(t, dr),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
								Id:   "derived_roles.my_derived_roles",
							},
						},
					},
				},
				{
					p:    ev,
					pset: compilePolicy(t, ev),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
								Id:   "export_variables.my_variables",
							},
						},
					},
				},
				{
					p:    rp,
					pset: compilePolicy(t, rp),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
								Id:   "resource.leave_request.vdefault",
							},
						},
					},
				},
				{
					p:    pp,
					pset: compilePolicy(t, pp),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
								Id:   "principal.john.vdefault",
							},
						},
					},
				},
			}

			for _, testCase := range testCases {
				t.Run(namer.PolicyKey(testCase.p), func(t *testing.T) {
					haveVariables := policy.ListVariables(testCase.p)
					require.Empty(t, cmp.Diff(testCase.expectedVariables, haveVariables, protocmp.Transform()))
				})
			}
		})

		t.Run("ListPolicySetVariables", func(t *testing.T) {
			testCases := []struct {
				p                 *policyv1.Policy
				pset              *runtimev1.RunnablePolicySet
				expectedVariables []*responsev1.InspectPoliciesResponse_Variable
			}{
				{
					p:    dr,
					pset: compilePolicy(t, dr),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL,
								Id:   "",
							},
						},
					},
				},
				{
					p:    ev,
					pset: compilePolicy(t, ev),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_EXPORTED,
								Id:   "",
							},
						},
					},
				},
				{
					p:    rp,
					pset: compilePolicy(t, rp),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
								Id:   "",
							},
						},
					},
				},
				{
					p:    pp,
					pset: compilePolicy(t, pp),
					expectedVariables: []*responsev1.InspectPoliciesResponse_Variable{
						{
							Name:  "geography",
							Value: "request.resource.attr.geography",
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_LOCAL_OR_IMPORTED,
								Id:   "",
							},
						},
					},
				},
			}

			for _, testCase := range testCases {
				if testCase.pset == nil {
					continue
				}

				t.Run(namer.PolicyKey(testCase.p), func(t *testing.T) {
					haveVariables := policy.ListPolicySetVariables(testCase.pset)
					require.Empty(t, cmp.Diff(testCase.expectedVariables, haveVariables, protocmp.Transform()))
				})
			}
		})
	})
}

func compilePolicy(t *testing.T, p *policyv1.Policy) *runtimev1.RunnablePolicySet {
	t.Helper()

	cu := &policy.CompilationUnit{}
	mID := namer.GenModuleID(p)
	cu.ModID = mID
	cu.AddDefinition(mID, p, parser.NewEmptySourceCtx())
	rps, err := compile.Compile(cu, schema.NewNopManager())
	require.NoError(t, err)

	return rps
}
