// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestProcessResultSet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		resultSet rego.ResultSet
		want      *EvalResult
		wantErr   bool
	}{
		{
			name:    "nil result set",
			wantErr: true,
		},
		{
			name:      "empty result set",
			resultSet: []rego.Result{},
			wantErr:   true,
		},
		{
			name: "more than one result",
			resultSet: []rego.Result{
				{},
				{},
			},
			wantErr: true,
		},
		{
			name: "empty expressions",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{},
				},
			},
			wantErr: true,
		},
		{
			name: "no effects",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{"wibble": "wobble"},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "wrong type for effects",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{codegen.EffectsIdent: 42},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid effects",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectsIdent: map[string]interface{}{
									"a": codegen.AllowEffectIdent,
									"b": codegen.DenyEffectIdent,
									"c": codegen.NoMatchEffectIdent,
								},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: &EvalResult{
				PolicyKey: "test",
				Effects: map[string]effectv1.Effect{
					"a": effectv1.Effect_EFFECT_ALLOW,
					"b": effectv1.Effect_EFFECT_DENY,
					"c": effectv1.Effect_EFFECT_NO_MATCH,
				},
			},
		},
		{
			name: "unknown effect",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{codegen.EffectsIdent: map[string]interface{}{"a": "blah"}},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "wrong type for effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectsIdent:               map[string]interface{}{"a": codegen.AllowEffectIdent},
								codegen.EffectiveDerivedRolesIdent: map[string]string{"a": "b"},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "non string effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectsIdent:               map[string]interface{}{"a": codegen.AllowEffectIdent},
								codegen.EffectiveDerivedRolesIdent: []interface{}{1, 2, 3},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectsIdent:               map[string]interface{}{"a": codegen.AllowEffectIdent},
								codegen.EffectiveDerivedRolesIdent: map[string]interface{}{},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: &EvalResult{
				PolicyKey:             "test",
				Effects:               map[string]effectv1.Effect{"a": effectv1.Effect_EFFECT_ALLOW},
				EffectiveDerivedRoles: nil,
			},
		},
		{
			name: "valid effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectsIdent:               map[string]interface{}{"a": codegen.AllowEffectIdent},
								codegen.EffectiveDerivedRolesIdent: []interface{}{"wibble", "wobble", "fubble"},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: &EvalResult{
				PolicyKey:             "test",
				Effects:               map[string]effectv1.Effect{"a": effectv1.Effect_EFFECT_ALLOW},
				EffectiveDerivedRoles: []string{"wibble", "wobble", "fubble"},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			have, err := processResultSet("test", tc.resultSet)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnexpectedResult)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, have)
		})
	}
}

func TestCELEvaluator(t *testing.T) {
	testCases := test.LoadTestCases(t, "cel_eval")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readCELTestCase(t, tcase.Input)
			cgr, err := codegen.GenerateCELCondition("test", tc.Condition, nil)
			require.NoError(t, err)

			prg, err := cgr.Program()
			require.NoError(t, err)

			requestJSON, err := protojson.Marshal(tc.Input)
			require.NoError(t, err)

			value, err := ast.ValueFromReader(bytes.NewReader(requestJSON))
			require.NoError(t, err)

			input, err := ast.ValueToInterface(value, nil)
			require.NoError(t, err)

			ceval := &CELConditionEvaluator{prg: prg}
			retVal, err := ceval.Eval(input)

			if tc.WantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.Want, retVal)
		})
	}
}

func readCELTestCase(t *testing.T, data []byte) *privatev1.CelTestCase {
	t.Helper()

	tc := &privatev1.CelTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
