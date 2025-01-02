// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package namer_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/test"
)

func TestFQN(t *testing.T) {
	testCases := []struct {
		name   string
		policy func() *policyv1.Policy
		want   string
	}{
		{
			name:   "derived roles",
			policy: func() *policyv1.Policy { return test.GenDerivedRoles(test.NoMod()) },
			want:   "cerbos.derived_roles.my_derived_roles",
		},
		{
			name:   "export constants",
			policy: func() *policyv1.Policy { return test.GenExportConstants(test.NoMod()) },
			want:   "cerbos.export_constants.my_constants",
		},
		{
			name:   "export variables",
			policy: func() *policyv1.Policy { return test.GenExportVariables(test.NoMod()) },
			want:   "cerbos.export_variables.my_variables",
		},
		{
			name:   "resource policy without scope",
			policy: func() *policyv1.Policy { return test.GenResourcePolicy(test.NoMod()) },
			want:   "cerbos.resource.leave_request.vdefault",
		},
		{
			name: "resource policy with scope",
			policy: func() *policyv1.Policy {
				p := test.GenResourcePolicy(test.NoMod())
				p.GetResourcePolicy().Scope = "acme.base"
				return p
			},
			want: "cerbos.resource.leave_request.vdefault/acme.base",
		},
		{
			name:   "principal policy without scope",
			policy: func() *policyv1.Policy { return test.GenPrincipalPolicy(test.NoMod()) },
			want:   "cerbos.principal.donald_duck.vdefault",
		},
		{
			name: "principal policy with scope",
			policy: func() *policyv1.Policy {
				p := test.GenPrincipalPolicy(test.NoMod())
				p.GetPrincipalPolicy().Scope = "acme.base"
				return p
			},
			want: "cerbos.principal.donald_duck.vdefault/acme.base",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := namer.FQN(tc.policy())
			require.Equal(t, tc.want, have)
		})
	}
}

func TestFQNTree(t *testing.T) {
	testCases := []struct {
		name   string
		policy func() *policyv1.Policy
		want   []string
	}{
		{
			name:   "derived roles",
			policy: func() *policyv1.Policy { return test.GenDerivedRoles(test.NoMod()) },
			want:   []string{"cerbos.derived_roles.my_derived_roles"},
		},
		{
			name:   "export constants",
			policy: func() *policyv1.Policy { return test.GenExportConstants(test.NoMod()) },
			want:   []string{"cerbos.export_constants.my_constants"},
		},
		{
			name:   "export variables",
			policy: func() *policyv1.Policy { return test.GenExportVariables(test.NoMod()) },
			want:   []string{"cerbos.export_variables.my_variables"},
		},
		{
			name:   "resource policy without scope",
			policy: func() *policyv1.Policy { return test.GenResourcePolicy(test.NoMod()) },
			want:   []string{"cerbos.resource.leave_request.vdefault"},
		},
		{
			name: "resource policy with scope",
			policy: func() *policyv1.Policy {
				p := test.GenResourcePolicy(test.NoMod())
				p.GetResourcePolicy().Scope = "acme.base.cloud"
				return p
			},
			want: []string{
				"cerbos.resource.leave_request.vdefault/acme.base.cloud",
				"cerbos.resource.leave_request.vdefault/acme.base",
				"cerbos.resource.leave_request.vdefault/acme",
				"cerbos.resource.leave_request.vdefault",
			},
		},
		{
			name:   "principal policy without scope",
			policy: func() *policyv1.Policy { return test.GenPrincipalPolicy(test.NoMod()) },
			want:   []string{"cerbos.principal.donald_duck.vdefault"},
		},
		{
			name: "principal policy with scope",
			policy: func() *policyv1.Policy {
				p := test.GenPrincipalPolicy(test.NoMod())
				p.GetPrincipalPolicy().Scope = "acme.base.cloud"
				return p
			},
			want: []string{
				"cerbos.principal.donald_duck.vdefault/acme.base.cloud",
				"cerbos.principal.donald_duck.vdefault/acme.base",
				"cerbos.principal.donald_duck.vdefault/acme",
				"cerbos.principal.donald_duck.vdefault",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := namer.FQNTree(tc.policy())
			require.Equal(t, tc.want, have)
		})
	}
}

func TestScopedModuleIDs(t *testing.T) {
	testCases := []struct {
		scope            string
		wantCountForTree int
	}{
		{
			scope:            "",
			wantCountForTree: 1,
		},
		{
			scope:            "a.b.c.d.e",
			wantCountForTree: 6,
		},
	}

	fns := []struct {
		kind    string
		fn      func(string, string, string, bool) []namer.ModuleID
		modIDFn func(string, string, string) namer.ModuleID
	}{
		{
			kind: "resource_policy",
			fn:   namer.ScopedResourcePolicyModuleIDs,
			modIDFn: func(resource, version, scope string) namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.ResourcePolicyFQN(resource, version, scope))
			},
		},
		{
			kind: "principal_policy",
			fn:   namer.ScopedPrincipalPolicyModuleIDs,
			modIDFn: func(principal, version, scope string) namer.ModuleID {
				return namer.GenModuleIDFromFQN(namer.PrincipalPolicyFQN(principal, version, scope))
			},
		},
	}

	t.Parallel()

	const (
		inputName    = "foo"
		inputVersion = "bar"
	)

	for _, fn := range fns {
		t.Run(fn.kind, func(t *testing.T) {
			t.Parallel()

			for _, tc := range testCases {
				t.Run(fmt.Sprintf("scope=%s/genTree=false", tc.scope), func(t *testing.T) {
					t.Parallel()

					have := fn.fn(inputName, inputVersion, tc.scope, false)
					require.Len(t, have, 1)
					require.Equal(t, fn.modIDFn(inputName, inputVersion, tc.scope), have[0])
				})

				t.Run(fmt.Sprintf("scope=%s/genTree=true", tc.scope), func(t *testing.T) {
					t.Parallel()

					have := fn.fn(inputName, inputVersion, tc.scope, true)
					require.Len(t, have, tc.wantCountForTree)
					require.Equal(t, fn.modIDFn(inputName, inputVersion, tc.scope), have[0])
					require.Equal(t, fn.modIDFn(inputName, inputVersion, ""), have[len(have)-1])

					idx := 1
					for i := len(tc.scope) - 1; i >= 0; i-- {
						if tc.scope[i] == '.' {
							wantModID := fn.modIDFn(inputName, inputVersion, tc.scope[:i])
							require.Equal(t, wantModID, have[idx], "Unexpected modID for scope %s", tc.scope[:i])
							idx++
						}
					}
				})
			}
		})
	}
}

func TestFQNSpecialChars(t *testing.T) {
	testCases := []struct {
		policyName   string
		fqnFunc      func(string, string, string) string
		wantFQN      string
		wantModuleID string
	}{
		{
			policyName:   "resource_name",
			fqnFunc:      namer.ResourcePolicyFQN,
			wantFQN:      "cerbos.resource.resource_name.vdefault/a.b.c",
			wantModuleID: "17187169266267860487",
		},
		{
			policyName:   "my-resource@some.domain-name/path",
			fqnFunc:      namer.ResourcePolicyFQN,
			wantFQN:      "cerbos.resource.my_resource_some.domain_name_path.vdefault/a.b.c",
			wantModuleID: "2652366422599377998",
		},
		{
			policyName:   "my-resource@@@@some.domain-name//path",
			fqnFunc:      namer.ResourcePolicyFQN,
			wantFQN:      "cerbos.resource.my_resource_some.domain_name_path.vdefault/a.b.c",
			wantModuleID: "2652366422599377998",
		},
		{
			policyName:   "arn:aws:sns:us-east-1:123456789012:topic-foo",
			fqnFunc:      namer.ResourcePolicyFQN,
			wantFQN:      "cerbos.resource.arn:aws:sns:us-east-1:123456789012:topic-foo.vdefault/a.b.c",
			wantModuleID: "9412675552925400030",
		},
		{
			policyName:   "principal_name",
			fqnFunc:      namer.PrincipalPolicyFQN,
			wantFQN:      "cerbos.principal.principal_name.vdefault/a.b.c",
			wantModuleID: "15622297473602434759",
		},
		{
			policyName:   "principal_name@email-domain.com",
			fqnFunc:      namer.PrincipalPolicyFQN,
			wantFQN:      "cerbos.principal.principal_name_email_domain.com.vdefault/a.b.c",
			wantModuleID: "9926962312262639256",
		},
		{
			policyName:   "principal_name@@@@@email-domain.com/foo",
			fqnFunc:      namer.PrincipalPolicyFQN,
			wantFQN:      "cerbos.principal.principal_name_email_domain.com_foo.vdefault/a.b.c",
			wantModuleID: "9473302746866088627",
		},
		{
			policyName:   "arn:aws:iam::123456789012:user/johndoe",
			fqnFunc:      namer.PrincipalPolicyFQN,
			wantFQN:      "cerbos.principal.arn:aws:iam::123456789012:user/johndoe.vdefault/a.b.c",
			wantModuleID: "5306719076896873049",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.policyName, func(t *testing.T) {
			haveFQN := tc.fqnFunc(tc.policyName, "default", "a.b.c")
			require.Equal(t, tc.wantFQN, haveFQN)
			haveModID := namer.GenModuleIDFromFQN(haveFQN)
			require.Equal(t, tc.wantModuleID, haveModID.String())
		})
	}
}
