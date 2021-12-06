// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/parser"
	"github.com/stretchr/testify/require"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

func Test_evaluateCondition(t *testing.T) {
	type args struct {
		expr      string
		condition *runtimev1.Condition
		input     *requestv1.ResourcesQueryPlanRequest
	}

	unparse := func(t *testing.T, expr *expr.CheckedExpr) string {
		t.Helper()
		require.NotNil(t, expr)
		source, err := parser.Unparse(expr.Expr, expr.SourceInfo)
		require.NoError(t, err)
		return source
	}

	compile := func(expr string, input *requestv1.ResourcesQueryPlanRequest) args {
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
			input:     input,
		}
	}
	tests := []struct {
		args           args
		wantExpression string
	}{
		{
			args:           compile("false", &requestv1.ResourcesQueryPlanRequest{}),
			wantExpression: "false",
		},
		{
			args: compile("P.attr.authenticated", &requestv1.ResourcesQueryPlanRequest{
				Principal: &enginev1.Principal{
					Attr: map[string]*structpb.Value{"authenticated": {Kind: &structpb.Value_BoolValue{BoolValue: true}}},
				},
			}),
			wantExpression: "true",
		},
		{
			args: compile("R.attr.owner == P.attr.name", &requestv1.ResourcesQueryPlanRequest{
				Principal: &enginev1.Principal{
					Attr: map[string]*structpb.Value{"name": {Kind: &structpb.Value_StringValue{StringValue: "harry"}}},
				},
			}),
			wantExpression: `R.attr.owner == "harry"`,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("Expr:%q", tt.args.expr), func(t *testing.T) {
			is := require.New(t)
			got, err := evaluateCondition(tt.args.condition, tt.args.input, nil)
			is.NoError(err)
			expression := got.GetExpression()
			is.Equal(tt.wantExpression, unparse(t, expression))
		})
	}
	for _, op := range []enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator{enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_AND, enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_OR} {
		attr := make(map[string]*structpb.Value)
		conds := make([]*runtimev1.Condition, len(tests))

		exprList := &runtimev1.Condition_ExprList{}
		var c *runtimev1.Condition
		if op == enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_AND {
			c = &runtimev1.Condition{Op: &runtimev1.Condition_All{All: exprList}}
		} else {
			c = &runtimev1.Condition{Op: &runtimev1.Condition_Any{Any: exprList}}
		}
		t.Run(fmt.Sprintf("%s operation", enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator_name[int32(op)]), func(t *testing.T) {
			is := require.New(t)
			for i := 0; i < len(tests); i++ {
				exprList.Expr = append(exprList.Expr, tests[i].args.condition)
				conds[i] = tests[i].args.condition
				input := tests[i].args.input
				if input.Principal != nil && input.Principal.Attr != nil {
					for k, v := range input.Principal.Attr {
						if _, ok := attr[k]; ok {
							t.Fatalf("Duplicate key %q", k)
						}
						attr[k] = v
					}
				}
			}
			got, err := evaluateCondition(c, &requestv1.ResourcesQueryPlanRequest{Principal: &enginev1.Principal{Attr: attr}}, nil)
			is.NotNil(got)
			is.NoError(err)
			operation := got.GetLogicalOperation()
			is.NotNil(operation)
			is.Equal(op, operation.Operator)
			for i := 0; i < len(tests); i++ {
				expression := operation.Nodes[i].GetExpression()
				is.Equal(tests[i].wantExpression, unparse(t, expression))
			}
		})
	}
}

func TestPartialEvaluationWithGlobalVars(t *testing.T) {
	is := require.New(t)

	env, err := conditions.StdPartialEnv.Extend(cel.Declarations(
		decls.NewVar("gb_us", decls.NewListType(decls.String)),
		decls.NewVar("gbLoc", decls.String),
		decls.NewVar("ca", decls.String),
		decls.NewVar("gb", decls.NewListType(decls.String)),
	))
	is.NoError(err)

	pvars, _ := cel.PartialVars(map[string]interface{}{
		"gbLoc": "en_GB",
		"gb_us": []string{"GB", "US"},
		"ca":    "ca",
	}, cel.AttributePattern("R"))

	variables := make(map[string]*expr.Expr)
	for k, txt := range map[string]string{
		"locale": `R.attr.language + "_" + R.attr.country`,
		"geo":    "R.attr.geo",
		"gb_us":  `["gb", "us"].map(t, t.upperAscii())`,
		"info":   `{"country": "GB", "language": "en"}`,
	} {
		e, iss := env.Compile(txt)
		is.Nil(iss, iss.Err())
		variables[k] = e.Expr()
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
			expr: "V.geo in (variables.gb_us + [ca]).map(t, t.upperAscii())",
			want: `R.attr.geo in ["GB", "US", "CA"]`,
		},
		{
			expr: `V.info.language + "_" + V.info.country == gbLoc`,
			want: "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			is := require.New(t)
			ast, iss := env.Compile(tt.expr)
			is.Nil(iss, iss.Err())
			e := ast.Expr()
			replaceVars(e, variables)
			ast = cel.ParsedExprToAst(&expr.ParsedExpr{Expr: e})
			prg, err := env.Program(ast, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
			is.NoError(err)
			out, det, err := prg.Eval(pvars)
			t.Log(types.IsUnknown(out))
			is.NoError(err)

			residual, err := env.ResidualAst(ast, det)
			is.NoError(err)
			astToString, err := cel.AstToString(residual)
			is.NoError(err)
			is.Equal(tt.want, astToString)
		})
	}
}
