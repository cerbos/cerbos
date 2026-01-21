// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types_test

import (
	"errors"
	"fmt"
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
	bindings := map[string]any{
		"request": &enginev1.Request{
			AuxData: &enginev1.AuxData{
				Jwt: map[string]*structpb.Value{
					"fooBar": structpb.NewStringValue("baz"),
				},
			},
		},
	}

	testCEL(t, []cel.EnvOption{
		cel.Types(&enginev1.Request{}),
		cel.VariableDecls(decls.NewVariable("request", types.MessageType[*enginev1.Request]())),
		types.Registry(),
	}, []celTestCase{
		{
			name:       "isSet snake case",
			expr:       "has(request.aux_data)",
			bindings:   bindings,
			wantResult: true,
		},
		{
			name:       "get snake case",
			expr:       "request.aux_data.jwt.fooBar",
			bindings:   bindings,
			wantResult: "baz",
		},
		{
			name:       "isSet camel case",
			expr:       "has(request.auxData)",
			bindings:   bindings,
			wantResult: true,
		},
		{
			name:       "get camel case",
			expr:       "request.auxData.jwt.fooBar",
			bindings:   bindings,
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
	})
}

type testRuntime struct{}

var _ types.Runtime = testRuntime{}

func (testRuntime) GetEffectiveDerivedRoles() []string {
	return []string{"foo", "bar"}
}

func TestRuntime(t *testing.T) {
	eager := map[string]any{"runtime": &enginev1.Runtime{EffectiveDerivedRoles: []string{"foo", "bar"}}}
	lazy := map[string]any{"runtime": testRuntime{}}

	testCEL(t, []cel.EnvOption{
		cel.Types(&enginev1.Runtime{}),
		cel.VariableDecls(decls.NewVariable("runtime", types.RuntimeType)),
		types.Registry(),
	}, []celTestCase{
		{
			name:       "eager isSet effective_derived_roles",
			bindings:   eager,
			expr:       "has(runtime.effective_derived_roles)",
			wantResult: true,
		},
		{
			name:       "eager isSet effectiveDerivedRoles",
			bindings:   eager,
			expr:       "has(runtime.effectiveDerivedRoles)",
			wantResult: true,
		},
		{
			name:       "eager get effective_derived_roles",
			bindings:   eager,
			expr:       "runtime.effective_derived_roles",
			wantResult: []string{"foo", "bar"},
		},
		{
			name:       "eager get effectiveDerivedRoles",
			bindings:   eager,
			expr:       "runtime.effectiveDerivedRoles",
			wantResult: []string{"foo", "bar"},
		},
		{
			name:       "lazy isSet effective_derived_roles",
			bindings:   lazy,
			expr:       "has(runtime.effective_derived_roles)",
			wantResult: true,
		},
		{
			name:       "lazy isSet effectiveDerivedRoles",
			bindings:   lazy,
			expr:       "has(runtime.effectiveDerivedRoles)",
			wantResult: true,
		},
		{
			name:       "lazy get effective_derived_roles",
			bindings:   lazy,
			expr:       "runtime.effective_derived_roles",
			wantResult: []string{"foo", "bar"},
		},
		{
			name:       "lazy get effectiveDerivedRoles",
			bindings:   lazy,
			expr:       "runtime.effectiveDerivedRoles",
			wantResult: []string{"foo", "bar"},
		},
		{
			name:           "isSet missing",
			expr:           "has(runtime.wat)",
			wantCompileErr: "undefined field 'wat'",
		},
		{
			name:           "get missing",
			expr:           "runtime.wat",
			wantCompileErr: "undefined field 'wat'",
		},
	})
}

type lazyFoo struct {
	value any
	err   error
}

var _ types.Variables = lazyFoo{}

func (lf lazyFoo) IsSet(name string) bool {
	return name == "foo"
}

func (lf lazyFoo) Get(name string) (any, error) {
	if name == "foo" {
		return lf.value, lf.err
	}
	return nil, fmt.Errorf("undefined field '%s'", name)
}

func TestVariables(t *testing.T) {
	eager := map[string]any{"V": types.VariablesMap(map[string]any{"foo": "bar"})}

	lazy := func(value any, err error) map[string]any {
		return map[string]any{"V": lazyFoo{value, err}}
	}

	testCEL(t, []cel.EnvOption{
		cel.VariableDecls(decls.NewVariable("V", types.VariablesType)),
		types.Registry(),
	}, []celTestCase{
		{
			name:       "eager isSet present",
			bindings:   eager,
			expr:       "has(V.foo)",
			wantResult: true,
		},
		{
			name:       "eager isSet absent",
			bindings:   eager,
			expr:       "has(V.bar)",
			wantResult: false,
		},
		{
			name:       "eager get present",
			bindings:   eager,
			expr:       "V.foo",
			wantResult: "bar",
		},
		{
			name:        "eager get absent",
			bindings:    eager,
			expr:        "V.bar",
			wantEvalErr: "undefined field 'bar'",
		},
		{
			name:       "lazy isSet present",
			bindings:   lazy("bar", nil),
			expr:       "has(V.foo)",
			wantResult: true,
		},
		{
			name:       "lazy isSet absent",
			bindings:   lazy("bar", nil),
			expr:       "has(V.bar)",
			wantResult: false,
		},
		{
			name:       "lazy get success",
			bindings:   lazy("bar", nil),
			expr:       "V.foo",
			wantResult: "bar",
		},
		{
			name:        "lazy get failure",
			bindings:    lazy(nil, errors.New("💥")),
			expr:        "V.foo",
			wantEvalErr: "💥",
		},
		{
			name:        "lazy get absent",
			bindings:    lazy("bar", nil),
			expr:        "V.bar",
			wantEvalErr: "undefined field 'bar'",
		},
	})
}

type celTestCase struct {
	name           string
	expr           string
	bindings       map[string]any
	wantCompileErr string
	wantResult     any
	wantEvalErr    string
}

func testCEL(t *testing.T, envOptions []cel.EnvOption, testCases []celTestCase) {
	t.Helper()

	env, err := cel.NewEnv(envOptions...)
	require.NoError(t, err, "Failed to create CEL environment")

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

			out, _, err := program.ContextEval(t.Context(), tc.bindings)
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
