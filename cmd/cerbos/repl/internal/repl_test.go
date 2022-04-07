// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"path/filepath"
	"testing"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"

	"github.com/google/cel-go/common/types/ref"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/test"
)

type DirectiveTest struct {
	Directive string
	Check     func(*testing.T, *mockOutput)
	WantErr   bool
}

func TestREPL(t *testing.T) {
	toRefVal := conditions.StdEnv.TypeAdapter().NativeToValue
	drPath := filepath.Join(test.PathToDir(t, "store"), "derived_roles", "derived_roles_01.yaml")
	drConds := loadConditionsFromDerivedRoles(t, drPath)

	testCases := []struct {
		name       string
		directives []DirectiveTest
	}{
		{
			name: "simple_expression",
			directives: []DirectiveTest{
				{
					Directive: `1+1`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, toRefVal(2), m.resultVal)
					},
				},
				{
					Directive: `_ + 1`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, toRefVal(3), m.resultVal)
					},
				},
			},
		},
		{
			name: "set_variable_and_reset",
			directives: []DirectiveTest{
				{
					Directive: `:let x = 1 + 5`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "x", m.resultName)
						require.Equal(t, toRefVal(6), m.resultVal)
					},
				},
				{
					Directive: `x * 2`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, toRefVal(12), m.resultVal)
					},
				},
				{
					Directive: `:reset`,
					Check:     func(t *testing.T, m *mockOutput) { t.Helper() },
				},
				{
					Directive: `x * 2`,
					WantErr:   true,
				},
				{
					Directive: `:let x = "test".charAt(1)`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "x", m.resultName)
						require.Equal(t, toRefVal("e"), m.resultVal)
					},
				},
			},
		},
		{
			name: "set_request_variable",
			directives: []DirectiveTest{
				{
					Directive: `:let request = {"principal":{"id":"john","roles":["employee"],"attr":{"scope":"foo.bar.baz.qux"}},"resource":{"id":"x1","kind":"leave_request","attr":{"scope":"foo.bar"}}}`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "request", m.resultName)

						want := &enginev1.CheckInput{
							Principal: &enginev1.Principal{
								Id:    "john",
								Roles: []string{"employee"},
								Attr:  map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar.baz.qux")},
							},
							Resource: &enginev1.Resource{
								Id:   "x1",
								Kind: "leave_request",
								Attr: map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar")},
							},
						}

						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
				{
					Directive: `P`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)

						want := &enginev1.Principal{
							Id:    "john",
							Roles: []string{"employee"},
							Attr:  map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar.baz.qux")},
						}
						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
				{
					Directive: `"employee" in request.principal.roles`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, toRefVal(true), m.resultVal)
					},
				},
				{
					Directive: `R`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)

						want := &enginev1.Resource{
							Id:   "x1",
							Kind: "leave_request",
							Attr: map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar")},
						}
						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
				{
					Directive: `hierarchy(request.resource.attr.scope).siblingOf(hierarchy("foo.baz"))`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, toRefVal(true), m.resultVal)
					},
				},
			},
		},
		{
			name: "set_principal_variable",
			directives: []DirectiveTest{
				{
					Directive: `:let P = {"id":"john","roles":["employee"],"attr":{"scope":"foo.bar.baz.qux"}}`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "P", m.resultName)

						want := &enginev1.Principal{
							Id:    "john",
							Roles: []string{"employee"},
							Attr:  map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar.baz.qux")},
						}
						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
				{
					Directive: `request`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)

						want := &enginev1.CheckInput{
							Principal: &enginev1.Principal{
								Id:    "john",
								Roles: []string{"employee"},
								Attr:  map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar.baz.qux")},
							},
						}
						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
			},
		},
		{
			name: "set_resource_variable",
			directives: []DirectiveTest{
				{
					Directive: `:let request.resource = {"id":"x1","kind":"leave_request","attr":{"scope":"foo.bar"}}`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "request.resource", m.resultName)

						want := &enginev1.Resource{
							Id:   "x1",
							Kind: "leave_request",
							Attr: map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar")},
						}
						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
				{
					Directive: `request`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)

						want := &enginev1.CheckInput{
							Resource: &enginev1.Resource{
								Id:   "x1",
								Kind: "leave_request",
								Attr: map[string]*structpb.Value{"scope": structpb.NewStringValue("foo.bar")},
							},
						}
						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
				{
					Directive: `hierarchy(R.attr.scope).siblingOf(hierarchy("foo.baz"))`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, toRefVal(true), m.resultVal)
					},
				},
			},
		},
		{
			name: "set_variables_variable",
			directives: []DirectiveTest{
				{
					Directive: `:let V = {"foo":"bar"}`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "V", m.resultName)

						want := map[string]any{"foo": "bar"}
						require.Equal(t, want, m.resultVal.Value())
					},
				},
				{
					Directive: `variables.foo`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, "bar", m.resultVal.Value())
					},
				},
			},
		},
		{
			name: "load_policy",
			directives: []DirectiveTest{
				{
					Directive: fmt.Sprintf(":load %s", drPath),
					Check: func(t *testing.T, output *mockOutput) {
						t.Helper()
						r := output.rules[0]
						rd, ok := r.(*policyv1.RoleDef)
						require.True(t, ok)
						condition, err := compile.Condition(rd.Condition)
						require.NoError(t, err)
						require.JSONEq(t, protojson.Format(drConds[2]), protojson.Format(condition))
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mockOut := &mockOutput{}
			repl, err := NewREPL(nil, mockOut)
			require.NoError(t, err)

			for _, d := range tc.directives {
				t.Run(d.Directive, func(t *testing.T) {
					err := repl.handleInput(d.Directive)
					if d.WantErr {
						require.Error(t, err)
						return
					}

					require.NoError(t, err)
					d.Check(t, mockOut)
				})
			}
		})
	}
}

type mockOutput struct {
	msg        string
	args       []any
	jsonObj    any
	resultName string
	resultVal  ref.Val
	rules      []any
	err        error
}

func (mo *mockOutput) Print(msg string, args ...any) {
	mo.msg = msg
	mo.args = args
}

func (mo *mockOutput) Println(args ...any) {
	mo.args = args
}

func (mo *mockOutput) PrintResult(name string, val ref.Val) {
	mo.resultName = name
	mo.resultVal = val
}

func (mo *mockOutput) PrintRule(_ int, rule any) error {
	mo.rules = append(mo.rules, rule)
	return nil
}

func (mo *mockOutput) PrintJSON(obj any) {
	mo.jsonObj = obj
}

func (mo *mockOutput) PrintErr(msg string, err error) {
	mo.msg = msg
	mo.err = err
}

func loadConditionsFromDerivedRoles(t *testing.T, path string) []*runtimev1.Condition {
	t.Helper()

	p := test.LoadPolicy(t, path)
	dr, ok := p.PolicyType.(*policyv1.Policy_DerivedRoles)
	require.True(t, ok)

	conds := make([]*runtimev1.Condition, len(dr.DerivedRoles.Definitions))
	for idx, rd := range dr.DerivedRoles.Definitions {
		cond, err := compile.Condition(rd.Condition)
		require.NoError(t, err)
		conds[idx] = cond
	}

	return conds
}
