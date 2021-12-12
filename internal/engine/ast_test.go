// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

type buildExprTestHelper struct {
	t  *testing.T
	is *require.Assertions
}

func (r buildExprTestHelper) mkValue(v interface{}) *structpb.Value {
	r.t.Helper()
	s, err := structpb.NewValue(v)
	r.is.NoError(err)
	return s
}

type any = interface{}

func (r buildExprTestHelper) assert(expr *responsev1.ResourcesQueryPlanResponse_Expression, op string, args []any) {
	r.t.Helper()
	is := r.is
	is.NotNil(expr)
	is.Equal(op, expr.Operator)
	is.Len(expr.Operands, len(args))

	for i, arg := range args {
		switch e := arg.(type) {
		case string:
			is.Equal(e, expr.Operands[i].GetVariable(), "type of node is %T", expr.Operands[i].Node)
		case *structpb.Value:
			is.Empty(cmp.Diff(e, expr.Operands[i].GetValue(), protocmp.Transform()))
		case func(expression *responsev1.ResourcesQueryPlanResponse_Expression):
			e(expr.Operands[i].GetExpression())
		default:
			r.t.Fatalf("unexpected argument type %T", e)
		}
	}
}

func Test_buildExpr(t *testing.T) {
	type (
		Ex   = responsev1.ResourcesQueryPlanResponse_Expression
		ExOp = responsev1.ResourcesQueryPlanResponse_Expression_Operand
	)
	is := require.New(t)
	h := buildExprTestHelper{t: t, is: is}
	tests := []struct {
		expr string
		must func(op *ExOp)
	}{
		{
			expr: `[1,a + 2,"q"]`,
			must: func(acc *ExOp) {
				h.assert(acc.GetExpression(), List, []any{
					h.mkValue(1),
					func(e *Ex) {
						h.assert(e, Add, []any{"a", h.mkValue(2)})
					},
					h.mkValue("q"),
				})
			},
		},
		{
			expr: `z + [2,3]`,
			must: func(acc *ExOp) {
				h.assert(acc.GetExpression(), Add, []any{
					"z",
					h.mkValue([]any{2, 3}),
				})
			},
		},
		{
			expr: `a[b].c`,
			must: func(acc *ExOp) {
				h.assert(acc.GetExpression(), Field, []any{
					func(e *Ex) {
						h.assert(e, Index, []any{"a", "b"})
					},
					"c",
				})
			},
		},
	}

	parse := func(s string) *exprpb.Expr {
		ast, iss := conditions.StdEnv.Parse(s)
		is.Nil(iss, iss.Err())
		return ast.Expr()
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			acc := new(ExOp)
			err := buildExpr(parse(tt.expr), acc)
			is.NoError(err)
			t.Log(protojson.Format(acc))
			tt.must(acc)
		})
	}
}
