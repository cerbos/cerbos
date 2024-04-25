// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/validator"
)

func TestReadPolicy(t *testing.T) {
	testCases := []struct {
		input string
		want  *policyv1.Policy
	}{
		{
			input: "resource_policy_01",
			want:  test.GenResourcePolicy(test.NoMod()),
		},
		{
			input: "principal_policy_01",
			want:  test.GenPrincipalPolicy(test.NoMod()),
		},
		{
			input: "derived_roles_01",
			want:  test.GenDerivedRoles(test.NoMod()),
		},
		{
			input: "export_variables_01",
			want:  test.GenExportVariables(test.NoMod()),
		},
	}

	dir := test.PathToDir(t, "policy_formats")

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			for _, format := range []string{"yaml", "json"} {
				t.Run(format, func(t *testing.T) {
					f, err := os.Open(filepath.Join(dir, tc.input+"."+format))
					require.NoError(t, err)

					defer f.Close()

					have, err := policy.ReadPolicy(f)
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(tc.want, have, protocmp.Transform(), protocmp.IgnoreFields(&policyv1.Policy{}, "json_schema")))
				})

				t.Run(format+"_source_context", func(t *testing.T) {
					have, haveCtx, err := policy.ReadPolicyWithSourceContext(os.DirFS(dir), tc.input+"."+format)
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(tc.want, have, protocmp.Transform(), protocmp.IgnoreFields(&policyv1.Policy{}, "json_schema")))
					require.NotNil(t, haveCtx)
				})
			}
		})
	}
}

func TestHash(t *testing.T) {
	inputs := []string{"resource_policy_01", "principal_policy_01", "derived_roles_01", "export_variables_01"}
	fs := os.DirFS(test.PathToDir(t, "policy_formats"))

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			yamlP, err := policy.ReadPolicyFromFile(fs, input+".yaml")
			require.NoError(t, err)

			jsonP, err := policy.ReadPolicyFromFile(fs, input+".json")
			require.NoError(t, err)

			require.Equal(t, policy.GetHash(yamlP), policy.GetHash(jsonP))
			require.Empty(t, cmp.Diff(yamlP, jsonP, protocmp.Transform(), protocmp.IgnoreFields(&policyv1.Policy{}, "json_schema")))
		})
	}
}

func TestReadFileWithMultiplePolicies(t *testing.T) {
	testCases := []struct {
		file    string
		wantErr bool
	}{
		{
			file:    "multiple_policies.yaml",
			wantErr: true,
		},
		{
			file:    "single_policy_trailing_spaces.yaml",
			wantErr: false,
		},
		{
			file:    "single_policy_others_commented.yaml",
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			input := filepath.Join(test.PathToDir(t, "policy_formats"), tc.file)
			f, err := os.Open(input)
			require.NoError(t, err)

			t.Cleanup(func() { _ = f.Close() })

			_, _, err = policy.ReadPolicyWithSourceContextFromReader(f)
			if tc.wantErr {
				require.ErrorIs(t, err, util.ErrMultipleYAMLDocs)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		name  string
		input func() proto.Message
	}{
		{
			name: "type=ResourcePolicy;issue=BadAPIVersion",
			input: func() proto.Message {
				obj := test.GenResourcePolicy(test.NoMod())
				obj.ApiVersion = "something"
				return obj
			},
		},
		{
			name: "type=ResourcePolicy;issue=EmptyResourceName",
			input: func() proto.Message {
				obj := test.GenResourcePolicy(test.NoMod())
				rp := obj.GetResourcePolicy()
				rp.Resource = ""
				obj.PolicyType = &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}

				return obj
			},
		},
		{
			name: "type=PrincipalPolicy;issue=BadAPIVersion",
			input: func() proto.Message {
				obj := test.GenPrincipalPolicy(test.NoMod())
				obj.ApiVersion = "something"
				return obj
			},
		},
		// TODO (cell) Cover other validation rules
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, validator.Validate(tc.input()))
		})
	}
}
