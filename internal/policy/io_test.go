// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

func TestReadPolicy(t *testing.T) {
	dir := test.PathToDir(t, "policy_formats")

	testCases := []struct {
		name    string
		input   string
		want    protoreflect.ProtoMessage
		wantErr bool
	}{
		{
			name:  "YAML ResourcePolicy",
			input: filepath.Join(dir, "resource_policy_01.yaml"),
			want:  test.GenResourcePolicy(test.NoMod()),
		},
		{
			name:  "JSON ResourcePolicy",
			input: filepath.Join(dir, "resource_policy_01.json"),
			want:  test.GenResourcePolicy(test.NoMod()),
		},
		{
			name:  "YAML PrincipalPolicy",
			input: filepath.Join(dir, "principal_policy_01.yaml"),
			want:  test.GenPrincipalPolicy(test.NoMod()),
		},
		{
			name:  "JSON PrincipalPolicy",
			input: filepath.Join(dir, "principal_policy_01.json"),
			want:  test.GenPrincipalPolicy(test.NoMod()),
		},
		{
			name:  "YAML DerivedRoles",
			input: filepath.Join(dir, "derived_roles_01.yaml"),
			want:  test.GenDerivedRoles(test.NoMod()),
		},
		{
			name:  "JSON DerivedRoles",
			input: filepath.Join(dir, "derived_roles_01.json"),
			want:  test.GenDerivedRoles(test.NoMod()),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// fmt.Println(protojson.Format(tc.want))
			f, err := os.Open(tc.input)
			require.NoError(t, err)

			defer f.Close()

			have, err := policy.ReadPolicy(f)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tc.want, have, protocmp.Transform()))
			}
		})
	}
}

func TestValidate(t *testing.T) {
	type validator interface {
		Validate() error
	}

	testCases := []struct {
		name  string
		input func() validator
	}{
		{
			name: "type=ResourcePolicy;issue=BadAPIVersion",
			input: func() validator {
				obj := test.GenResourcePolicy(test.NoMod())
				obj.ApiVersion = "something"
				return obj
			},
		},
		{
			name: "type=ResourcePolicy;issue=BadResourceName",
			input: func() validator {
				obj := test.GenResourcePolicy(test.NoMod())
				rp := obj.GetResourcePolicy()
				rp.Resource = "a?;#"
				obj.PolicyType = &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}

				return obj
			},
		},
		{
			name: "type=ResourcePolicy;issue=EmptyResourceName",
			input: func() validator {
				obj := test.GenResourcePolicy(test.NoMod())
				rp := obj.GetResourcePolicy()
				rp.Resource = ""
				obj.PolicyType = &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}

				return obj
			},
		},
		{
			name: "type=ResourcePolicy;issue=NoResourceRules",
			input: func() validator {
				obj := test.GenResourcePolicy(test.NoMod())
				rp := obj.GetResourcePolicy()
				rp.Rules = nil
				obj.PolicyType = &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}

				return obj
			},
		},
		{
			name: "type=PrincipalPolicy;issue=BadAPIVersion",
			input: func() validator {
				obj := test.GenPrincipalPolicy(test.NoMod())
				obj.ApiVersion = "something"
				return obj
			},
		},
		// TODO (cell) Cover other validation rules
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj := tc.input()
			require.Error(t, obj.Validate())
		})
	}
}
