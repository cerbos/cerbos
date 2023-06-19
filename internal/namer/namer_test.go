// Copyright 2021-2023 Zenauth Ltd.
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			have := namer.FQNTree(tc.policy())
			require.Equal(t, tc.want, have)
		})
	}
}

func TestPolicyCoords(t *testing.T) {
	testCases := []struct {
		key     string
		want    namer.PolicyCoords
		wantErr bool
	}{
		{
			key:  "derived_roles.my_derived_roles",
			want: namer.PolicyCoords{Kind: "DERIVED_ROLES", Name: "my_derived_roles"},
		},
		{
			key:  "principal.donald_duck.vdefault",
			want: namer.PolicyCoords{Kind: "PRINCIPAL", Name: "donald_duck", Version: "default"},
		},
		{
			key:  "principal.donald_duck.vdefault/acme.base.cloud",
			want: namer.PolicyCoords{Kind: "PRINCIPAL", Name: "donald_duck", Version: "default", Scope: "acme.base.cloud"},
		},
		{
			key:  "resource.salary_record.vdefault",
			want: namer.PolicyCoords{Kind: "RESOURCE", Name: "salary_record", Version: "default"},
		},
		{
			key:  "resource.salary_record.vdefault/acme.base",
			want: namer.PolicyCoords{Kind: "RESOURCE", Name: "salary_record", Version: "default", Scope: "acme.base"},
		},
		{
			key:     "resource.xxx.yyy.zzz.vdefault/acme.base",
			wantErr: true,
		},
		{
			key:     "resource.salary_record/acme.base",
			wantErr: true,
		},
		{
			key:     "blah.salary_record.vdefault/acme.base",
			wantErr: true,
		},
		{
			key:     "blah",
			wantErr: true,
		},
		{
			key:     "",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("key=%q", tc.key), func(t *testing.T) {
			have, err := namer.PolicyCoordsFromPolicyKey(tc.key)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, have)
			require.Equal(t, tc.key, have.PolicyKey())
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
		fn := fn
		t.Run(fn.kind, func(t *testing.T) {
			t.Parallel()

			for _, tc := range testCases {
				tc := tc
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
