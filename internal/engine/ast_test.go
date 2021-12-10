// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"testing"
)

type tEx struct {
	t  *testing.T
	is *require.Assertions
}

func (r tEx) mkValue(v interface{}) *structpb.Value {
	r.t.Helper()
	s, err := structpb.NewValue(v)
	r.is.NoError(err)
	return s
}

type tExArgs = []interface{}

func (r tEx) rEx(expr *responsev1.ResourcesQueryPlanResponse_Expression, op string, args tExArgs) {
	r.t.Helper()
	is := r.is
	is.NotNil(expr)
	is.Equal(op, expr.Operator)
	is.Len(expr.Operands, len(args))

	for i, arg := range args {
		switch e := arg.(type) {
		case string:
			is.Equal(e, expr.Operands[i].GetVariable())
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
		Ex = responsev1.ResourcesQueryPlanResponse_Expression
	)
	is := require.New(t)
	parse := func(s string) *exprpb.Expr {
		ast, iss := conditions.StdEnv.Parse(s)
		is.Nil(iss, iss.Err())
		return ast.Expr()
	}
	tex := tEx{t: t, is: is}
	tests := []struct {
		name string
	}{
		{"first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := new(responsev1.ResourcesQueryPlanResponse_Expression_Operand)

			err := buildExpr(parse(`[1,a + 2,"q"]`), acc)
			is.NoError(err)
			t.Log(protojson.Format(acc))

			tex.rEx(acc.GetExpression(), List, tExArgs{
				tex.mkValue(1),
				func(e *Ex) {
					tex.rEx(e, Add, tExArgs{"a", tex.mkValue(2)})
				},
				tex.mkValue("q"),
			})
		})
	}
}
