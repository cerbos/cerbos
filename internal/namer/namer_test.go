// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package namer_test

import (
	"testing"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/stretchr/testify/require"
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
