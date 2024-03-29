// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package policy_test

import (
	"fmt"
	"strconv"
	"testing"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/schema"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
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

func TestActions(t *testing.T) {
	dr := test.GenDerivedRoles(test.NoMod())
	ev := test.GenExportVariables(test.NoMod())
	rp := test.NewResourcePolicyBuilder("leave_request", "default").
		WithRules(
			test.
				NewResourceRule("a", "b").
				WithRoles("user").
				Build(),
			test.
				NewResourceRule("a").
				WithRoles("admin").
				Build(),
		).Build()
	pp := test.NewPrincipalPolicyBuilder("john", "default").
		WithRules(
			test.NewPrincipalRuleBuilder("leave_request").
				AllowAction("a").
				AllowAction("b").
				DenyAction("c").
				Build(),
			test.NewPrincipalRuleBuilder("purchase_order").
				AllowAction("a").
				DenyAction("c").
				Build(),
		).Build()
	testCases := []struct {
		p               *policyv1.Policy
		pset            *runtimev1.RunnablePolicySet
		expectedActions []string
	}{
		{
			p:               dr,
			pset:            compilePolicy(t, dr),
			expectedActions: []string{},
		},
		{
			p:               ev,
			pset:            compilePolicy(t, ev),
			expectedActions: []string{},
		},
		{
			p:               rp,
			pset:            compilePolicy(t, rp),
			expectedActions: []string{"a", "b"},
		},
		{
			p:               pp,
			pset:            compilePolicy(t, pp),
			expectedActions: []string{"a", "b", "c"},
		},
	}

	t.Run("Actions", func(t *testing.T) {
		for _, testCase := range testCases {
			haveActions := policy.Actions(testCase.p)
			require.ElementsMatch(t, testCase.expectedActions, haveActions)
		}
	})

	t.Run("PSActions", func(t *testing.T) {
		for _, testCase := range testCases {
			haveActions := policy.PSActions(testCase.pset)
			require.ElementsMatch(t, testCase.expectedActions, haveActions)
		}
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
