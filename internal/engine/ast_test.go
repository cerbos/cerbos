// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/util"
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
		must func(op *ExOp) // use this
		yaml string         // and/or this to assert
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
				h.assert(acc.GetExpression(), GetField, []any{
					func(e *Ex) {
						h.assert(e, Index, []any{"a", "b"})
					},
					"c",
				})
			},
		},
		{
			expr: `a[b].c.d`,
			yaml: `
expression:
  operator: "get-field"
  operands:
    - expression:
        operator: "get-field"
        operands:
          - expression:
              operator: index
              operands:
                - variable: a
                - variable: b
          - variable: c
    - variable: d
`,
			must: func(acc *ExOp) {
				h.assert(acc.GetExpression(), GetField, []any{
					func(e *Ex) {
						h.assert(e, GetField, []any{
							func(e *Ex) {
								h.assert(e, Index, []any{"a", "b"})
							},
							"c",
						})
					},
					"d",
				})
			},
		},
		{
			expr: `{a:2, b: 3}`,
			yaml: `
expression:
  operator: struct
  operands:
    - expression:
        operator: "set-field"
        operands:
          - variable: a
          - value: 2
    - expression:
        operator: "set-field"
        operands:
          - variable: b
          - value: 3
`,
		},
		{
			expr: "x.filter(t, t > 0)",
			yaml: `
        expression:
          operator: loop
          operands:
          - expression:
              operands:
              - expression:
                  operands:
                  - expression:
                      operands:
                      - variable: t
                      - value: 0
                      operator: gt
                  - expression:
                      operands:
                      - variable: __result__
                      - expression:
                          operands:
                          - variable: t
                          operator: list
                      operator: add
                  - variable: __result__
                  operator: _?_:_
              operator: loop-step
          - expression:
              operands:
              - value: true
              operator: loop-condition
          - expression:
              operands:
              - variable: __result__
              operator: loop-result
          - expression:
              operands:
              - value: []
              operator: loop-accu-init
          - expression:
              operands:
              - variable: x
              operator: loop-iter-range
          - expression:
              operands:
              - variable: t
              operator: loop-iter-var
          - expression:
              operands:
              - variable: __result__
              operator: loop-accu-var
`,
		},
		{
			expr: "x.map(t, t.upperAscii())",
			yaml: `
        expression:
          operands:
          - expression:
              operands:
              - expression:
                  operands:
                  - variable: __result__
                  - expression:
                      operands:
                      - expression:
                          operands:
                          - variable: t
                          operator: upperAscii
                      operator: list
                  operator: add
              operator: loop-step
          - expression:
              operands:
              - value: true
              operator: loop-condition
          - expression:
              operands:
              - variable: __result__
              operator: loop-result
          - expression:
              operands:
              - value: []
              operator: loop-accu-init
          - expression:
              operands:
              - variable: x
              operator: loop-iter-range
          - expression:
              operands:
              - variable: t
              operator: loop-iter-var
          - expression:
              operands:
              - variable: __result__
              operator: loop-accu-var
          operator: loop
`,
		},
		{
			expr: "f(a,3)",
			must: func(acc *ExOp) {
				h.assert(acc.GetExpression(), "f", []any{"a", h.mkValue(3)})
			},
		},
		{
			expr: "x.f(a,3)",
			must: func(acc *ExOp) {
				h.assert(acc.GetExpression(), "f", []any{"x", "a", h.mkValue(3)})
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
			data, err := protojson.Marshal(acc)
			is.NoError(err)
			data, err = yaml.JSONToYAML(data)
			is.NoError(err)
			t.Logf("\n%s", string(data))

			if tt.must != nil {
				tt.must(acc)
			}
			if tt.yaml != "" {
				expected := new(ExOp)
				err = util.ReadJSONOrYAML(strings.NewReader(tt.yaml), expected)
				is.NoError(err)
				is.Empty(cmp.Diff(expected, acc, protocmp.Transform()))
			}
		})
	}
}
