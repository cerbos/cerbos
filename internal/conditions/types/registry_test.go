// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types_test

import (
	"reflect"
	"testing"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions/types"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestJSONFields(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Types(&enginev1.Request{}),
		cel.VariableDecls(decls.NewVariable("request", types.MessageType[*enginev1.Request]())),
		types.Registry(),
	)
	require.NoError(t, err, "Failed to create CEL environment")

	vars := map[string]any{
		"request": &enginev1.Request{
			AuxData: &enginev1.AuxData{
				Jwt: map[string]*structpb.Value{
					"fooBar": structpb.NewStringValue("baz"),
				},
			},
		},
	}

	testCases := []struct {
		name           string
		expr           string
		wantResult     any
		wantCompileErr string
		wantEvalErr    string
	}{
		{
			name:       "isSet snake case",
			expr:       "has(request.aux_data)",
			wantResult: true,
		},
		{
			name:       "get snake case",
			expr:       "request.aux_data.jwt.fooBar",
			wantResult: "baz",
		},
		{
			name:       "isSet camel case",
			expr:       "has(request.auxData)",
			wantResult: true,
		},
		{
			name:       "get camel case",
			expr:       "request.auxData.jwt.fooBar",
			wantResult: "baz",
		},
		{
			name:           "isSet missing",
			expr:           "has(request.wat)",
			wantCompileErr: "undefined field 'wat'",
		},
		{
			name:           "get missing",
			expr:           "request.wat",
			wantCompileErr: "undefined field 'wat'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(tc.expr)
			if tc.wantCompileErr == "" {
				require.NoError(t, issues.Err(), "Failed to compile CEL expression")
			} else {
				require.ErrorContains(t, issues.Err(), tc.wantCompileErr, "Expected compile error")
				return
			}

			program, err := env.Program(ast)
			require.NoError(t, err, "Failed to create CEL program")

			out, _, err := program.ContextEval(t.Context(), vars)
			if tc.wantEvalErr == "" {
				require.NoError(t, err, "Failed to evaluate CEL program")
			} else {
				require.ErrorContains(t, err, tc.wantEvalErr, "Expected evaluation error")
				return
			}

			haveResult, err := out.ConvertToNative(reflect.TypeOf(tc.wantResult))
			require.NoError(t, err, "Failed to convert CEL program result to %T", tc.wantResult)
			require.Equal(t, tc.wantResult, haveResult, "Unexpected result from CEL evaluation")
		})
	}
}
