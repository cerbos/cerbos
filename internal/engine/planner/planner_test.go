// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
	"github.com/stretchr/testify/require"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/planner/internal"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/cel-go/interpreter"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_evaluateCondition(t *testing.T) {
	type args struct {
		expr      string
		condition *runtimev1.Condition
		request   *enginev1.Request
	}

	unparse := func(t *testing.T, expr *expr.CheckedExpr) string {
		t.Helper()
		require.NotNil(t, expr)
		astExpr, err := celast.ProtoToExpr(expr.Expr)
		require.NoError(t, err)
		srcInfo, err := celast.ProtoToSourceInfo(expr.SourceInfo)
		require.NoError(t, err)
		source, err := parser.Unparse(astExpr, srcInfo)
		require.NoError(t, err)
		return source
	}

	compile := func(expr string, request *enginev1.Request) args {
		ast, iss := conditions.StdEnv.Compile(expr)
		require.Nil(t, iss, "Error is %s", iss.Err())
		checkedExpr, err := cel.AstToCheckedExpr(ast)
		require.NoError(t, err)
		c := &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{
			Original: expr,
			Checked:  checkedExpr,
		}}}
		return args{
			expr:      expr,
			condition: c,
			request:   request,
		}
	}
	tests := []struct {
		args args
		want string
	}{
		{
			args: compile("false", &enginev1.Request{}),
			want: "false",
		},
		{
			args: compile("P.attr.authenticated", &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{"authenticated": structpb.NewBoolValue(true)},
				},
			}),
			want: "true",
		},
		{
			args: compile("request.principal.attr.authenticated", &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{"authenticated": structpb.NewBoolValue(true)},
				},
			}),
			want: "true",
		},
		{
			args: compile(`R.attr.department == "marketing"`, &enginev1.Request{}),
			want: `R.attr.department == "marketing"`,
		},
		{
			args: compile("R.attr.owner == P.attr.name", &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{"name": structpb.NewStringValue("harry")},
				},
			}),
			want: `R.attr.owner == "harry"`,
		},
		{
			args: compile(`R.kind == P.attr.resource_name`, &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{"resource_name": structpb.NewStringValue("resource-1")},
				},
				Resource: &enginev1.Request_Resource{
					Kind: "resource-1",
				},
			}),
			want: "true",
		},
		{ // this test case reproduced the issue #1340
			args: compile(`P.attr.department_role[R.attr.department] == "ADMIN"`, &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{
						"department_role": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{"marketing": structpb.NewStringValue("ADMIN")}}),
					},
				},
				Resource: &enginev1.Request_Resource{
					Attr: map[string]*structpb.Value{
						"department": structpb.NewStringValue("marketing"),
					},
				},
			}),
			want: "true",
		},
		{ // swap struct and index
			args: compile(`R.attr.department_role[P.attr.department] == "ADMIN"`, &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{
						"department": structpb.NewStringValue("marketing"),
					},
				},
				Resource: &enginev1.Request_Resource{
					Attr: map[string]*structpb.Value{
						"department_role": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{"marketing": structpb.NewStringValue("ADMIN")}}),
					},
				},
			}),
			want: "true",
		},
		{
			args: compile(`request.principal.attr.department_role[request.resource.attr.department] == "ADMIN"`, &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{
						"department_role": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{"marketing": structpb.NewStringValue("ADMIN")}}),
					},
				},
				Resource: &enginev1.Request_Resource{
					Attr: map[string]*structpb.Value{
						"department": structpb.NewStringValue("marketing"),
					},
				},
			}),
			want: "true",
		},
		{
			args: compile(`P.attr.role_department["ADMIN"] == R.attr.department`, &enginev1.Request{
				Principal: &enginev1.Request_Principal{
					Attr: map[string]*structpb.Value{
						"role_department": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{"ADMIN": structpb.NewStringValue("marketing")}}),
					},
				},
				Resource: &enginev1.Request_Resource{
					Attr: map[string]*structpb.Value{
						"department": structpb.NewStringValue("marketing"),
					},
				},
			}),
			want: "true",
		},
	}
	evalCtx := &EvalContext{TimeFn: time.Now}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("Expr:%q", tt.args.expr), func(t *testing.T) {
			is := require.New(t)
			got, err := evalCtx.EvaluateCondition(tt.args.condition, tt.args.request, nil, nil, nil, nil)
			is.NoError(err)
			expression := got.GetExpression()
			is.Equal(tt.want, unparse(t, expression))
		})
	}

	// filter test cases with "complex" expression, i.e. having calls.
	// then group these expressions in logical expressions
	j := 0
	for i := 0; i < len(tests); i++ {
		if tests[i].want != "true" && tests[i].want != "false" {
			tests[j] = tests[i]
			j++
		}
	}
	tests = tests[:j]
	for _, opStr := range []string{"OPERATOR_AND", "OPERATOR_OR"} {
		op := enginev1.PlanResourcesAst_LogicalOperation_Operator_value[opStr]
		resourceAttr := make(map[string]*structpb.Value)
		principalAttr := make(map[string]*structpb.Value)
		conds := make([]*runtimev1.Condition, len(tests))

		exprList := &runtimev1.Condition_ExprList{}
		c := new(runtimev1.Condition)
		if opStr == "OPERATOR_AND" {
			c.Op = &runtimev1.Condition_All{All: exprList}
		} else {
			c.Op = &runtimev1.Condition_Any{Any: exprList}
		}
		t.Run(opStr, func(t *testing.T) {
			is := require.New(t)
			for i := 0; i < len(tests); i++ {
				exprList.Expr = append(exprList.Expr, tests[i].args.condition)
				conds[i] = tests[i].args.condition
				request := tests[i].args.request
				if request.GetPrincipal().GetAttr() != nil {
					for k, v := range request.Principal.Attr {
						if v1, ok := principalAttr[k]; ok && !cmp.Equal(v, v1, protocmp.Transform()) {
							t.Fatalf("Duplicate key %q", k)
						}
						principalAttr[k] = v
					}
				}
				if request.GetResource().GetAttr() != nil {
					for k, v := range request.Resource.Attr {
						if v1, ok := resourceAttr[k]; ok && !cmp.Equal(v, v1, protocmp.Transform()) {
							t.Fatalf("Duplicate key %q", k)
						}
						resourceAttr[k] = v
					}
				}
			}
			got, err := evalCtx.EvaluateCondition(c, &enginev1.Request{
				Principal: &enginev1.Request_Principal{Attr: principalAttr},
				Resource:  &enginev1.Request_Resource{Attr: resourceAttr},
			}, nil, nil, nil, nil)
			is.NotNil(got)
			is.NoError(err)
			operation := got.GetLogicalOperation()
			is.NotNil(operation)
			is.Equal(op, int32(operation.Operator))
			for i := 0; i < len(tests); i++ {
				expression := operation.Nodes[i].GetExpression()
				is.Equal(tests[i].want, unparse(t, expression))
			}
		})
	}
}

// TestResidualExpr compares two approaches to evaluate `residual expression`.
// 1. ast := env.ResidualAst(); ast.Expr()
// 2. ResidualExpr()
// The former is the built-in approach, but unlike the latter doesn't support CEL comprehensions.
func TestResidualExpr(t *testing.T) {
	tests := []string{
		"V.geo",
		"V.locale == gbLoc",
		"V.geo in (gb_us + [ca]).map(t, t.upperAscii())",
		"V.geo in (V.gb_us2 + [ca]).map(t, t.upperAscii())",
		"V.geo in (variables.gb_us + [ca]).map(t, t.upperAscii())",
		`V.info.language + "_" + V.info.country == gbLoc`,
		`has(R.attr.geo) && R.attr.geo in ["GB", "US"]`,
		"has(V.info.language)",
		`now() > timestamp("2021-04-20T00:00:00Z") && R.attr.geo in ["GB", "US"]`,
		`timestamp(R.attr.lastAccessed) > now()`,
	}

	env, pvars, variables := setupEnv(t)
	ignoreID := cmpopts.IgnoreMapEntries(func(k string, _ any) bool { return k == "id" })
	for _, tt := range tests {
		s := tt
		t.Run(s, func(t *testing.T) {
			now := time.Now()
			nowFn := func() time.Time {
				return now
			}

			is := require.New(t)
			ast, iss := env.Compile(s)
			is.Nil(iss, iss.Err())
			e, err := cel.AstToCheckedExpr(ast)
			is.NoError(err)
			ex, err := replaceVars(e.Expr, variables)
			is.NoError(err)
			ast = cel.ParsedExprToAst(&expr.ParsedExpr{Expr: ex})
			_, det, err := conditions.Eval(env, ast, pvars, nowFn, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
			is.NoError(err)
			residualAst, err := env.ResidualAst(ast, det)
			is.NoError(err)
			re, err := cel.AstToParsedExpr(residualAst)
			is.NoError(err)
			wantResidualExpr := re.Expr

			ast = cel.ParsedExprToAst(&expr.ParsedExpr{Expr: ex})
			_, det, err = conditions.Eval(env, ast, pvars, nowFn, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
			is.NoError(err)
			haveResidualExpr, err := ResidualExpr(ast, det)
			is.NoError(err)
			p := newPartialEvaluator(env, pvars, nowFn)
			err = p.evalComprehensionBody(haveResidualExpr)
			is.NoError(err)
			is.Empty(cmp.Diff(wantResidualExpr, haveResidualExpr, protocmp.Transform(), ignoreID))
		})
	}
}

func TestPartialEvaluationWithGlobalVars(t *testing.T) {
	now := time.Now()
	nowStr := now.Format(time.RFC3339Nano)
	nowFn := func() time.Time {
		return now
	}

	tests := []struct {
		expr, want string
	}{
		{
			expr: "V.geo",
			want: "R.attr.geo",
		},
		{
			expr: "V.locale == gbLoc",
			want: `R.attr.language + "_" + R.attr.country == "en_GB"`,
		},
		{
			expr: "V.geo in (gb_us + [ca]).map(t, t.upperAscii())",
			want: `R.attr.geo in ["GB", "US", "CA"]`,
		},
		{
			expr: "V.geo in (V.gb_us2 + [ca]).map(t, t.upperAscii())",
			want: `R.attr.geo in ["GB", "US", "CA"]`,
		},
		{
			expr: "V.geo in (variables.gb_us + [ca]).map(t, t.upperAscii())",
			want: `R.attr.geo in ["GB", "US", "CA"]`,
		},
		{
			expr: `V.info.language + "_" + V.info.country == gbLoc`,
			want: "true",
		},
		{
			expr: `has(R.attr.geo) && R.attr.geo in ["GB", "US"]`,
			want: `has(R.attr.geo) && R.attr.geo in ["GB", "US"]`,
		},
		{
			expr: "has(V.info.language)",
			want: "true",
		},
		{
			expr: "R.attr.items.filter(x, x.price > T)",
			want: "R.attr.items.filter(x, x.price > 100)",
		},
		{
			expr: `now() > timestamp("2021-04-20T00:00:00Z") && R.attr.geo in ["GB", "US"]`,
			want: `R.attr.geo in ["GB", "US"]`,
		},
		{
			expr: `R.attr.items.filter(x, x.price > now())`,
			want: fmt.Sprintf(`R.attr.items.filter(x, x.price > timestamp("%s"))`, nowStr),
		},
		{
			expr: `timestamp(R.attr.lastAccessed) > now()`,
			want: fmt.Sprintf(`timestamp(R.attr.lastAccessed) > timestamp("%s")`, nowStr),
		},
		{
			expr: `intersect(R.attr.workspaces, V.gb_us)`,
			want: `intersect(R.attr.workspaces, ["GB", "US"])`,
		},
	}

	env, pvars, variables := setupEnv(t)
	ignoreID := cmpopts.IgnoreMapEntries(func(k string, _ any) bool { return k == "id" })
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			var err error
			is := require.New(t)
			ast, iss := env.Compile(tt.expr)
			is.Nil(iss, iss.Err())

			pe, err := cel.AstToParsedExpr(ast)
			is.NoError(err)
			e, err := replaceVars(pe.Expr, variables)
			is.NoError(err)
			ast = cel.ParsedExprToAst(&expr.ParsedExpr{Expr: e})
			_, det, err := conditions.Eval(env, ast, pvars, nowFn, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
			is.NoError(err)
			haveExpr, err := ResidualExpr(ast, det)
			is.NoError(err)
			p := partialEvaluator{env: env, vars: pvars, nowFn: nowFn}
			err = p.evalComprehensionBody(haveExpr)
			internal.UpdateIDs(haveExpr)
			is.NoError(err)

			wantAst, iss := env.Parse(tt.want)
			pe, err = cel.AstToParsedExpr(wantAst)
			is.NoError(err)
			wantExpr := pe.Expr
			internal.UpdateIDs(wantExpr)
			is.Nil(iss, iss.Err())
			is.Empty(cmp.Diff(wantExpr, haveExpr, protocmp.Transform(), ignoreID),
				"{\"got\": %s,\n\"want\": %s}", protojson.Format(haveExpr), protojson.Format(wantExpr))
		})
	}
}

func setupEnv(t *testing.T) (*cel.Env, interpreter.PartialActivation, map[string]*expr.Expr) {
	t.Helper()

	env, err := conditions.StdEnv.Extend(cel.Declarations(
		decls.NewVar("gb_us", decls.NewListType(decls.String)),
		decls.NewVar("gbLoc", decls.String),
		decls.NewVar("ca", decls.String),
		decls.NewVar("T", decls.Int),
	))
	require.NoError(t, err)

	pvars, _ := cel.PartialVars(map[string]any{
		"gbLoc": "en_GB",
		"gb_us": []string{"GB", "US"},
		"ca":    "ca",
		"T":     100,
	}, cel.AttributePattern("R").QualString("attr"))

	variables := make(map[string]*expr.Expr)
	for k, txt := range map[string]string{
		"locale": `R.attr.language + "_" + R.attr.country`,
		"geo":    "R.attr.geo",
		"gb_us2": "gb_us",
		"gb_us":  `["gb", "us"].map(t, t.upperAscii())`,
		"info":   `{"country": "GB", "language": "en"}`,
	} {
		ast, iss := env.Compile(txt)
		require.Nil(t, iss, iss.Err())
		ex, err := cel.AstToParsedExpr(ast)
		require.NoError(t, err)
		variables[k] = ex.Expr
	}
	return env, pvars, variables
}

func TestNormaliseFilter(t *testing.T) {
	tcases := test.LoadTestCases(t, "query_planner_filter")

	for _, tcase := range tcases {
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readQPFilterTestCase(t, tcase.Input)
			haveFilter := normaliseFilter(tc.Input)
			require.Empty(t, cmp.Diff(tc.WantFilter, haveFilter, protocmp.Transform()))

			haveStr := filterToString(haveFilter)
			require.Equal(t, tc.WantString, haveStr)
		})
	}
}

func readQPFilterTestCase(tb testing.TB, data []byte) *privatev1.QueryPlannerFilterTestCase {
	tb.Helper()

	tc := &privatev1.QueryPlannerFilterTestCase{}
	require.NoError(tb, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
