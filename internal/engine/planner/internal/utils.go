// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

func UpdateIDs(e *exprpb.Expr) {
	var n int64
	ids := make(map[*exprpb.Expr]int64)

	var impl func(e *exprpb.Expr)
	impl = func(e *exprpb.Expr) {
		if e == nil {
			return
		}
		if id, ok := ids[e]; ok {
			e.Id = id
		} else {
			n++
			ids[e] = n
			e.Id = n
		}

		switch e := e.ExprKind.(type) {
		case *exprpb.Expr_SelectExpr:
			impl(e.SelectExpr.Operand)
		case *exprpb.Expr_CallExpr:
			impl(e.CallExpr.Target)
			for _, arg := range e.CallExpr.Args {
				impl(arg)
			}
		case *exprpb.Expr_StructExpr:
			for _, entry := range e.StructExpr.Entries {
				impl(entry.GetMapKey())
				impl(entry.GetValue())
			}
		case *exprpb.Expr_ComprehensionExpr:
			ce := e.ComprehensionExpr
			impl(ce.IterRange)
			impl(ce.AccuInit)
			impl(ce.LoopStep)
			impl(ce.LoopCondition)
			impl(ce.Result)
		case *exprpb.Expr_ListExpr:
			for _, element := range e.ListExpr.Elements {
				impl(element)
			}
		}
	}
	impl(e)
}

func MkCallExpr(op string, args ...*exprpb.Expr) *exprpb.Expr {
	e := &exprpb.Expr{
		ExprKind: &exprpb.Expr_CallExpr{CallExpr: &exprpb.Expr_Call{
			Function: op,
			Args:     args,
		}},
	}
	return e
}

func MkSelectExpr(operand *exprpb.Expr, field string) *exprpb.Expr {
	return &exprpb.Expr{
		ExprKind: &exprpb.Expr_SelectExpr{
			SelectExpr: &exprpb.Expr_Select{
				Operand: operand,
				Field:   field,
			},
		},
	}
}
