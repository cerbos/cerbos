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
