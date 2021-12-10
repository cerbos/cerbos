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

func mkValue(t *testing.T, v interface{}) *structpb.Value {
	t.Helper()
	s, err := structpb.NewValue(v)
	require.NoError(t, err)
	return s
}

func Test_buildExpr(t *testing.T) {
	is := require.New(t)
	parse := func(s string) *exprpb.Expr {
		ast, iss := conditions.StdEnv.Parse(s)
		is.Nil(iss, iss.Err())
		return ast.Expr()
	}
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

			expr := acc.GetExpression()
			is.NotNil(expr)
			is.Equal(expr.Operator, List)
			is.Len(expr.Operands, 3)

			// first operand
			op := expr.Operands[0]
			is.Empty(cmp.Diff(mkValue(t, 1), op.GetValue(), protocmp.Transform()))

			// second operand
			op = expr.Operands[1]
			{
				expr := op.GetExpression()
				is.NotNil(expr)
				is.Equal(expr.Operator, Add)
				is.Len(expr.Operands, 2)

				is.Equal("a", expr.Operands[0].GetVariable())
				is.Empty(cmp.Diff(mkValue(t, 2), expr.Operands[1].GetValue(), protocmp.Transform()))
			}

			// third operand
			op = expr.Operands[2]
			is.Empty(cmp.Diff(mkValue(t, "q"), op.GetValue(), protocmp.Transform()))
		})
	}
}
