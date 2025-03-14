// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/cel-go/common/types/ref"
	"github.com/google/go-cmp/cmp"
	"github.com/pterm/pterm"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/test"
)

type DirectiveTest struct {
	Directive string
	Check     func(*testing.T, *mockOutput)
	WantErr   bool
}

func TestREPL(t *testing.T) {
	toRefVal := conditions.StdEnv.CELTypeAdapter().NativeToValue
	drPath := filepath.Join(test.PathToDir(t, "store"), "derived_roles", "derived_roles_01.yaml")
	rpPath := filepath.Join(test.PathToDir(t, "store"), "resource_policies", "policy_01.yaml")
	ppPath := filepath.Join(test.PathToDir(t, "store"), "principal_policies", "policy_01.yaml")
	rpImportVariablesPath := filepath.Join(test.PathToDir(t, "store"), "resource_policies", "policy_09.yaml")
	rpAnyAllNonePath := filepath.Join(test.PathToDir(t, "store"), "resource_policies", "policy_18.yaml")
	ecPath := filepath.Join(test.PathToDir(t, "store"), "export_constants", "export_constants_01.yaml")
	evPath := filepath.Join(test.PathToDir(t, "store"), "export_variables", "export_variables_01.yaml")
	drConds := loadConditionsFromPolicy(t, drPath)
	rpConds := loadConditionsFromPolicy(t, rpPath)
	ppConds := loadConditionsFromPolicy(t, ppPath)

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
			name: "set_constants_variable",
			directives: []DirectiveTest{
				{
					Directive: `:let C = {"foo":42}`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "C", m.resultName)

						want := map[string]any{"foo": float64(42)}
						require.Equal(t, want, m.resultVal.Value())
					},
				},
				{
					Directive: `constants.foo`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, float64(42), m.resultVal.Value())
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
			name: "set_globals_variable",
			directives: []DirectiveTest{
				{
					Directive: `:let G = {"foo":"bar"}`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "G", m.resultName)

						want := map[string]any{"foo": "bar"}
						require.Equal(t, want, m.resultVal.Value())
					},
				},
				{
					Directive: `globals.foo`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, "bar", m.resultVal.Value())
					},
				},
			},
		},
		{
			name: "load_derived_roles",
			directives: []DirectiveTest{
				{
					Directive: fmt.Sprintf(":load %s", drPath),
					Check: func(t *testing.T, output *mockOutput) {
						t.Helper()
						for idx, r := range output.rules {
							rd, ok := r.(*policyv1.RoleDef)
							require.True(t, ok)
							condition, err := compile.Condition(rd.Condition)
							require.NoError(t, err)
							require.JSONEq(t, protojson.Format(drConds[idx]), protojson.Format(condition))
						}
					},
				},
			},
		},
		{
			name: "load_resource_policy",
			directives: []DirectiveTest{
				{
					Directive: fmt.Sprintf(":load %s", rpPath),
					Check: func(t *testing.T, output *mockOutput) {
						t.Helper()
						for idx, r := range output.rules {
							rr, ok := r.(*policyv1.ResourceRule)
							require.True(t, ok)
							condition, err := compile.Condition(rr.Condition)
							require.NoError(t, err)
							require.JSONEq(t, protojson.Format(rpConds[idx]), protojson.Format(condition))
						}
					},
				},
				{
					Directive: `V.principal_location`,
					WantErr:   true,
				},
				{
					Directive: `:let P = {"id":"john","roles":["employee"],"attr":{"ip_address":"10.20.1.2"}}`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, "P", m.resultName)

						want := &enginev1.Principal{
							Id:    "john",
							Roles: []string{"employee"},
							Attr:  map[string]*structpb.Value{"ip_address": structpb.NewStringValue("10.20.1.2")},
						}

						require.Empty(t, cmp.Diff(want, m.resultVal.Value(), protocmp.Transform()))
					},
				},
				{
					Directive: `V.principal_location`,
					Check: func(t *testing.T, m *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, m.resultName)
						require.Equal(t, "GB", m.resultVal.Value())
					},
				},
			},
		},
		{
			name: "load_principal_policy",
			directives: []DirectiveTest{
				{
					Directive: fmt.Sprintf(":load %s", ppPath),
					Check: func(t *testing.T, output *mockOutput) {
						t.Helper()
						for idx, r := range output.rules {
							pr, ok := r.(*policyv1.PrincipalRule)
							for _, action := range pr.Actions {
								require.True(t, ok)
								condition, err := compile.Condition(action.Condition)
								require.NoError(t, err)
								require.JSONEq(t, protojson.Format(ppConds[idx]), protojson.Format(condition))
							}
						}
					},
				},
			},
		},
		{
			name: "load_policy_with_imported_variables",
			directives: []DirectiveTest{
				{
					Directive: fmt.Sprintf(":load %s", rpImportVariablesPath),
					WantErr:   true,
				},
				{
					Directive: fmt.Sprintf(":load %s", ecPath),
				},
				{
					Directive: fmt.Sprintf(":load %s", evPath),
				},
				{
					Directive: fmt.Sprintf(":load %s", rpImportVariablesPath),
				},
				{
					Directive: "V.foo",
					Check: func(t *testing.T, output *mockOutput) {
						t.Helper()
						require.Equal(t, lastResultVar, output.resultName)
						require.Equal(t, toRefVal(float64(42)), output.resultVal)
					},
				},
			},
		},
		{
			name: "exec",
			directives: []DirectiveTest{
				{
					Directive: fmt.Sprintf(":load %s", rpAnyAllNonePath),
				},
				{
					Directive: anyAllNoneResourceDirective(true, true),
				},
				{
					Directive: ":exec #0",
					Check:     checkAnyAllNoneTree(true, true, "all", true),
				},
				{
					Directive: ":exec #1",
					Check:     checkAnyAllNoneTree(true, true, "any", true),
				},
				{
					Directive: ":exec #2",
					Check:     checkAnyAllNoneTree(true, true, "none", false),
				},
				{
					Directive: anyAllNoneResourceDirective(true, false),
				},
				{
					Directive: ":exec #0",
					Check:     checkAnyAllNoneTree(true, false, "all", false),
				},
				{
					Directive: ":exec #1",
					Check:     checkAnyAllNoneTree(true, false, "any", true),
				},
				{
					Directive: ":exec #2",
					Check:     checkAnyAllNoneTree(true, false, "none", false),
				},
				{
					Directive: anyAllNoneResourceDirective(false, false),
				},
				{
					Directive: ":exec #0",
					Check:     checkAnyAllNoneTree(false, false, "all", false),
				},
				{
					Directive: ":exec #1",
					Check:     checkAnyAllNoneTree(false, false, "any", false),
				},
				{
					Directive: ":exec #2",
					Check:     checkAnyAllNoneTree(false, false, "none", true),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockOut := &mockOutput{}
			repl, err := NewREPL(nil, mockOut)
			require.NoError(t, err)

			for _, d := range tc.directives {
				t.Run(d.Directive, func(t *testing.T) {
					err := repl.handleInput(t.Context(), d.Directive)
					if d.WantErr {
						require.Error(t, err)
						return
					}

					require.NoError(t, err)
					if d.Check != nil {
						d.Check(t, mockOut)
					}
				})
			}
		})
	}
}

func anyAllNoneResourceDirective(a, b bool) string {
	return fmt.Sprintf(`:let R = {"kind":"any_all_none","id":"1","attr":{"a":%t,"b":%t}}`, a, b)
}

func checkAnyAllNoneTree(a, b bool, operator string, result bool) func(*testing.T, *mockOutput) {
	return func(t *testing.T, output *mockOutput) {
		t.Helper()
		require.Equal(t, pterm.LeveledList{
			{Level: 0, Text: fmt.Sprintf("%s [%t]", operator, result)},
			{Level: 1, Text: fmt.Sprintf("R.attr.a [%t]", a)},
			{Level: 1, Text: fmt.Sprintf("R.attr.b [%t]", b)},
		}, output.tree)
	}
}

func TestIsTerminated(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"{foo: bar}", true},
		{"[foo: bar]", true},
		{"(foo: bar)", true},
		{"{'foo': 'bar'}", true},
		{"['foo': 'bar']", true},
		{"('foo': 'bar')", true},
		{"{\"foo\": \"bar\"}", true},
		{"[\"foo\": \"bar\"]", true},
		{"(\"foo\": \"bar\")", true},
		{"{\"foo\": \"bar\"}", true},
		{"foo\"bar\" ('baz')", true},
		{"\"foo\\\"bar\\\" ('baz'\"", true},
		{"\"foo_'_bar_\\\"_baz\"", true},
		{"{foo: bar}\\", false},
		{"foo_'_bar_\\\"_baz", false},
		{"foo_'_bar_baz", false},
		{"foo\\\"bar\\\" ('baz'", false},
		{"{'foo': 'bar'", false},
	}

	for idx, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase_%d", idx), func(t *testing.T) {
			stack := &runeStack{}
			_, actual := isTerminated(tc.input, stack)
			require.True(t, actual == tc.expected, tc.input)
		})
	}
}

type mockOutput struct {
	msg        string
	args       []any
	jsonObj    any
	yamlObj    any
	resultName string
	resultVal  ref.Val
	rules      []proto.Message
	tree       pterm.LeveledList
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

func (mo *mockOutput) PrintRule(_ int, rule proto.Message) error {
	mo.rules = append(mo.rules, rule)
	return nil
}

func (mo *mockOutput) PrintJSON(obj any) {
	mo.jsonObj = obj
}

func (mo *mockOutput) PrintYAML(obj proto.Message, _ int) {
	mo.yamlObj = obj
}

func (mo *mockOutput) PrintTree(tree pterm.LeveledList) error {
	mo.tree = tree
	return nil
}

func (mo *mockOutput) PrintErr(msg string, err error) {
	mo.msg = msg
	mo.err = err
}

func loadConditionsFromPolicy(t *testing.T, path string) []*runtimev1.Condition {
	t.Helper()

	p := test.LoadPolicy(t, path)

	var conds []*runtimev1.Condition
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		for _, rule := range pt.ResourcePolicy.Rules {
			if rule.Condition != nil {
				cond, err := compile.Condition(rule.Condition)
				require.NoError(t, err)
				conds = append(conds, cond)
			}
		}
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition != nil {
				cond, err := compile.Condition(def.Condition)
				require.NoError(t, err)
				conds = append(conds, cond)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if action.Condition != nil {
					cond, err := compile.Condition(action.Condition)
					require.NoError(t, err)
					conds = append(conds, cond)
				}
			}
		}
	}

	return conds
}

func TestComplete(t *testing.T) {
	testRulesProtos := make([]proto.Message, 3)

	wd, _ := os.Getwd()

	expFilesStrs := []string{
		"testdata/complete/file.json",
		"testdata/complete/file.yaml",
		"testdata/complete/file.yml",
		"testdata/complete/sub/file.json",
		"testdata/complete/sub/file.yaml",
		"testdata/complete/sub/file.yml",
	}

	expFileLoads := make([]string, len(expFilesStrs))
	for i, f := range expFilesStrs {
		expFileLoads[i] = fmt.Sprintf(":load %s", filepath.FromSlash(f))
	}

	expFileAbsLoads := make([]string, len(expFilesStrs))
	for i, f := range expFilesStrs {
		expFileAbsLoads[i] = fmt.Sprintf(":load %s", filepath.Join(wd, filepath.FromSlash(f)))
	}

	testCases := []struct {
		input    string
		expected []string
		rules    []proto.Message
	}{
		{"1 ", []string{}, nil},
		{":l", []string{":let", ":load"}, nil},
		{":lo", []string{":load"}, nil},

		{":load", []string{":load"}, nil},
		{
			fmt.Sprintf(":load %s", filepath.Join("testdata", "complete")),
			expFileLoads,
			nil,
		},
		{
			fmt.Sprintf(":load %s", filepath.Join(wd, "testdata", "complete")),
			expFileAbsLoads,
			nil,
		},

		{
			":let ",
			[]string{
				":let C",
				":let G",
				":let P",
				":let R",
				":let V",
				":let _",
				":let constants",
				":let globals",
				":let request",
				":let runtime",
				":let variables",
			},
			nil,
		},

		{
			":exec ",
			[]string{
				":exec #0",
				":exec #1",
				":exec #2",
			},
			testRulesProtos,
		},
		{
			":exec #",
			[]string{
				":exec #0",
				":exec #1",
				":exec #2",
			},
			testRulesProtos,
		},
		{
			":exec #2",
			[]string{
				":exec #2",
			},
			testRulesProtos,
		},
		{
			":exec #3",
			[]string{},
			testRulesProtos,
		},
		{
			":exec #abc",
			[]string{},
			testRulesProtos,
		},
		{
			":exec abc",
			[]string{},
			testRulesProtos,
		},
	}

	for idx, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase_%d", idx), func(t *testing.T) {
			mockOut := &mockOutput{}
			repl, err := NewREPL(nil, mockOut)
			require.NoError(t, err)

			if tc.rules != nil {
				repl.policy = &policyHolder{rules: tc.rules}
			}

			require.Equal(t, tc.expected, repl.Complete(tc.input))
		})
	}
}
