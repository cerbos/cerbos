// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	celast "github.com/google/cel-go/common/ast"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type IDGen struct {
	ids map[int64]int64
	c   int64
}

func NewIDGen() *IDGen {
	return &IDGen{
		ids: make(map[int64]int64),
	}
}
func (g *IDGen) Remap(id int64) int64 {
	if n, ok := g.ids[id]; ok {
		return n
	}
	g.c++
	g.ids[id] = g.c
	return g.c
}
func RenumberIDs(e celast.Expr) {
	e.RenumberIDs(NewIDGen().Remap)
}
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

func MkListExpr(elems []celast.Expr) celast.Expr {
	fact := celast.NewExprFactory()
	return fact.NewList(0, elems, nil)
}

func MkListExprProto(elems []*exprpb.Expr) *exprpb.Expr {
	return &exprpb.Expr{
		ExprKind: &exprpb.Expr_ListExpr{
			ListExpr: &exprpb.Expr_CreateList{
				Elements: elems,
			},
		},
	}
}

func MkCallExpr(op string, args ...celast.Expr) celast.Expr {
	fact := celast.NewExprFactory()
	return fact.NewCall(0, op, args...)
}

func MkCallExprProto(op string, args ...*exprpb.Expr) *exprpb.Expr {
	e := &exprpb.Expr{
		ExprKind: &exprpb.Expr_CallExpr{CallExpr: &exprpb.Expr_Call{
			Function: op,
			Args:     args,
		}},
	}
	return e
}

func MkSelectExpr(operand celast.Expr, field string) celast.Expr {
	fact := celast.NewExprFactory()
	return fact.NewSelect(0, operand, field)
}

func MkSelectExprProto(operand *exprpb.Expr, field string) *exprpb.Expr {
	return &exprpb.Expr{
		ExprKind: &exprpb.Expr_SelectExpr{
			SelectExpr: &exprpb.Expr_Select{
				Operand: operand,
				Field:   field,
			},
		},
	}
}
