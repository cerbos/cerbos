package compile

import (
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/codegen"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

func TestProcessResultSet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		resultSet rego.ResultSet
		want      EvalResult
		wantErr   bool
	}{
		{
			name:    "nil result set",
			wantErr: true,
			want:    defaultEvalResult,
		},
		{
			name:      "empty result set",
			resultSet: []rego.Result{},
			wantErr:   true,
			want:      defaultEvalResult,
		},
		{
			name: "more than one result",
			resultSet: []rego.Result{
				{},
				{},
			},
			wantErr: true,
			want:    defaultEvalResult,
		},
		{
			name: "empty expressions",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{},
				},
			},
			wantErr: true,
			want:    defaultEvalResult,
		},
		{
			name: "no effect",
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
			want:    defaultEvalResult,
		},
		{
			name: "wrong type for effect",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{codegen.EffectIdent: 42},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
			want:    defaultEvalResult,
		},
		{
			name: "allow effect",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{codegen.EffectIdent: codegen.AllowEffectIdent},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: EvalResult{
				Effect: sharedv1.Effect_EFFECT_ALLOW,
			},
		},
		{
			name: "deny effect",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{codegen.EffectIdent: codegen.DenyEffectIdent},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: EvalResult{
				Effect: sharedv1.Effect_EFFECT_DENY,
			},
		},
		{
			name: "no_match effect",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{codegen.EffectIdent: codegen.NoMatchEffectIdent},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: EvalResult{
				Effect: sharedv1.Effect_EFFECT_NO_MATCH,
			},
		},
		{
			name: "unknown effect",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{codegen.EffectIdent: "blah"},
							Text:  namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: EvalResult{
				Effect: sharedv1.Effect_EFFECT_DENY,
			},
		},
		{
			name: "wrong type for effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectIdent:                codegen.AllowEffectIdent,
								codegen.EffectiveDerivedRolesIdent: map[string]string{"a": "b"},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
			want: EvalResult{
				Effect: sharedv1.Effect_EFFECT_ALLOW,
			},
		},
		{
			name: "non string effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectIdent:                codegen.AllowEffectIdent,
								codegen.EffectiveDerivedRolesIdent: []interface{}{1, 2, 3},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			wantErr: true,
			want: EvalResult{
				Effect: sharedv1.Effect_EFFECT_ALLOW,
			},
		},
		{
			name: "empty effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectIdent:                codegen.AllowEffectIdent,
								codegen.EffectiveDerivedRolesIdent: []interface{}{},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: EvalResult{
				Effect:                sharedv1.Effect_EFFECT_ALLOW,
				EffectiveDerivedRoles: []string{},
			},
		},
		{
			name: "valid effective derived roles",
			resultSet: []rego.Result{
				{
					Expressions: []*rego.ExpressionValue{
						{
							Value: map[string]interface{}{
								codegen.EffectIdent:                codegen.AllowEffectIdent,
								codegen.EffectiveDerivedRolesIdent: []interface{}{"wibble", "wobble", "fubble"},
							},
							Text: namer.QueryForPrincipal("x", "default"),
						},
					},
				},
			},
			want: EvalResult{
				Effect:                sharedv1.Effect_EFFECT_ALLOW,
				EffectiveDerivedRoles: []string{"wibble", "wobble", "fubble"},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			have, err := processResultSet(tc.resultSet)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnexpectedResult)
				require.Equal(t, tc.want, have)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, have)
		})
	}
}
