// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestJSONSchemasAreValid(t *testing.T) {
	var paths []string

	err := filepath.WalkDir("jsonschema", func(path string, _ fs.DirEntry, err error) error {
		if strings.HasSuffix(path, ".schema.json") {
			paths = append(paths, path)
		}

		return err
	})

	require.NoError(t, err, "failed to walk schema directory")
	require.NotEmpty(t, paths, "didn't find any schemas")

	compiler := jsonschema.NewCompiler()

	for _, path := range paths {
		_, err := compiler.Compile(path)
		assert.NoError(t, err, "invalid schema %q", path)
	}
}

func TestValidatePoliciesWithJSONSchema(t *testing.T) {
	policySchema, err := jsonschema.NewCompiler().Compile("jsonschema/cerbos/policy/v1/Policy.schema.json")
	require.NoError(t, err, "failed to compile policy schema")

	tests := []struct {
		policy any
		title  string
		valid  bool
	}{
		{
			title:  "valid derived roles",
			policy: jsonify(t, test.GenDerivedRoles(test.NoMod())),
			valid:  true,
		},
		{
			title:  "valid principal policy",
			policy: jsonify(t, test.GenPrincipalPolicy(test.NoMod())),
			valid:  true,
		},
		{
			title:  "valid resource policy",
			policy: jsonify(t, test.GenResourcePolicy(test.NoMod())),
			valid:  true,
		},
		{
			title:  "invalid: wrong type",
			policy: 42,
			valid:  false,
		},
		{
			title:  "invalid: empty object",
			policy: map[string]any{},
			valid:  false,
		},
		{
			title:  "invalid: missing policy body",
			policy: map[string]any{"apiVersion": "api.cerbos.dev/v1"},
			valid:  false,
		},
		{
			title: "invalid: wrong API version",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.ApiVersion = "api.cerbos.dev/v0"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid derived roles: name doesn't match pattern",
			policy: func() any {
				policy := test.GenDerivedRoles(test.NoMod())
				policy.GetDerivedRoles().Name = "?"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid derived roles: missing definitions",
			policy: func() any {
				policy := test.GenDerivedRoles(test.NoMod())
				policy.GetDerivedRoles().Definitions = nil
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid derived roles: definition name doesn't match pattern",
			policy: func() any {
				policy := test.GenDerivedRoles(test.NoMod())
				policy.GetDerivedRoles().Definitions[0].Name = "?"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid derived roles: definition missing parent roles",
			policy: func() any {
				policy := test.GenDerivedRoles(test.NoMod())
				policy.GetDerivedRoles().Definitions[0].ParentRoles = nil
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid derived roles: definition has duplicate parent roles",
			policy: func() any {
				policy := test.GenDerivedRoles(test.NoMod())
				policy.GetDerivedRoles().Definitions[0].ParentRoles = []string{"admin", "admin"}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid principal policy: empty principal",
			policy: func() any {
				policy := test.GenPrincipalPolicy(test.NoMod())
				policy.GetPrincipalPolicy().Principal = ""
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid principal policy: version doesn't match pattern",
			policy: func() any {
				policy := test.GenPrincipalPolicy(test.NoMod())
				policy.GetPrincipalPolicy().Version = "?"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid principal policy: rule resource missing",
			policy: func() any {
				policy := test.GenPrincipalPolicy(test.NoMod())
				policy.GetPrincipalPolicy().Rules[0].Resource = ""
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid principal policy: rule action missing action",
			policy: func() any {
				policy := test.GenPrincipalPolicy(test.NoMod())
				policy.GetPrincipalPolicy().Rules[0].Actions[0].Action = ""
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid principal policy: rule action effect not allowed",
			policy: func() any {
				policy := test.GenPrincipalPolicy(test.NoMod())
				policy.GetPrincipalPolicy().Rules[0].Actions[0].Effect = effectv1.Effect_EFFECT_NO_MATCH
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid principal policy: rule action name doesn't match pattern",
			policy: func() any {
				policy := test.GenPrincipalPolicy(test.NoMod())
				policy.GetPrincipalPolicy().Rules[0].Actions[0].Name = "?"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid principal policy: scope doesn't match pattern",
			policy: func() any {
				policy := test.GenPrincipalPolicy(test.NoMod())
				policy.GetPrincipalPolicy().Scope = "?"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: empty kind",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Resource = ""
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: version doesn't match pattern",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Version = "-1"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: duplicate import derived roles",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().ImportDerivedRoles = []string{"derived_roles", "derived_roles"}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: import derived role doesn't match pattern",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().ImportDerivedRoles = []string{"?"}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: rule missing actions",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].Actions = nil
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: duplicate rule actions",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].Actions = []string{"view", "view"}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: empty rule action",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].Actions = []string{""}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: duplicate rule derived roles",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].DerivedRoles = []string{"owner", "owner"}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: rule derived role doesn't match pattern",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].DerivedRoles = []string{"?"}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: duplicate rule roles",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].Roles = []string{"owner", "owner"}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: rule role is empty",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].Roles = []string{""}
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: rule effect not allowed",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].Effect = effectv1.Effect_EFFECT_NO_MATCH
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: rule name doesn't match pattern",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Rules[0].Name = "?"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
		{
			title: "invalid resource policy: scope doesn't match pattern",
			policy: func() any {
				policy := test.GenResourcePolicy(test.NoMod())
				policy.GetResourcePolicy().Scope = "?"
				return jsonify(t, policy)
			}(),
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			err := policySchema.Validate(tt.policy)
			if tt.valid {
				require.NoError(t, err)
			} else {
				var validationError *jsonschema.ValidationError
				require.ErrorAs(t, err, &validationError)
			}
		})
	}
}

func jsonify(t *testing.T, message proto.Message) map[string]any {
	t.Helper()

	data, err := protojson.Marshal(message)
	require.NoError(t, err, "failed to marshal message to JSON")

	var result map[string]any
	err = json.Unmarshal(data, &result)
	require.NoError(t, err, "failed to unmarshal message from JSON")

	return result
}
