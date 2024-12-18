// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"errors"
	"fmt"
	"github.com/google/cel-go/common/operators"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type lambdaAST struct {
	iterRange *exprpb.Expr
	expr      *exprpb.Expr
	expr2     *exprpb.Expr
	iterVar   string
	iterVar2  string
	operator  string
}

func getTransformMapExpression(w *wrapper) (string, *exprpb.Expr, error) {
	const nTransformMapEntryArgs = 2
	const nTransformMapArgs = 3
	n := w.getArgsLen()
	var op string

	switch n {
	case nTransformMapArgs:
		op = TransformMap
	case nTransformMapEntryArgs:
		op = TransformMapEntry
	default:
		return "", nil, fmt.Errorf("unexpected args #, got: %d", n)
	}
	return op, w.getArg(n - 1).e(), nil
}

var ErrExpectedSortBy = errors.New("expected sortBy comprehension")

const sortByFuncName = "sortBy"

func mkSortByAST(e *exprpb.Expr_Comprehension) (*lambdaAST, error) {
	const function = "sortByAssociatedKeys"
	w := (*wrapper)(e.Result)
	var e2 *exprpb.Expr_Comprehension
	if e2 = w.getArg(0).e().GetComprehensionExpr(); e2 == nil || w.getArgsLen() != 1 {
		return nil, fmt.Errorf("%w, got %s", ErrExpectedSortBy, e.String())
	}
	obj := &lambdaAST{
		operator:  sortByFuncName,
		iterRange: e.AccuInit,
		iterVar:   e2.IterVar,
		expr:      (*wrapper)(e2.LoopStep).getArg(1).getListElement(0).e(),
	}
	if obj.expr == nil {
		return nil, fmt.Errorf("%w, got %s", ErrExpectedSortBy, e.String())
	}
	return obj, nil
}

func buildLambdaAST(e *exprpb.Expr_Comprehension) (*lambdaAST, error) {
	var function string
	var loopStep *wrapper
	switch ls := e.LoopStep.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		function = ls.CallExpr.Function
		loopStep = (*wrapper)(e.LoopStep)
	case *exprpb.Expr_IdentExpr:
		return mkSortByAST(e)
	default:
		return nil, fmt.Errorf("expected loop-step expression type CallExpr, got: %T", ls)
	}
	if call := e.LoopStep.GetCallExpr(); call != nil {
		function = call.Function
		loopStep = (*wrapper)(e.LoopStep)
	} else {
		return nil, fmt.Errorf("expected loop-step expression type CallExpr, got: %T", e.LoopStep.ExprKind)
	}
	obj := &lambdaAST{
		iterVar:   e.IterVar,
		iterVar2:  e.IterVar2,
		iterRange: e.IterRange,
	}
	switch function {
	case operators.LogicalAnd:
		obj.operator = All
		obj.expr = loopStep.getArg(1).e()
	case operators.LogicalOr:
		obj.operator = Exists
		obj.expr = loopStep.getArg(1).e()
	case operators.Add:
		obj.operator = Map
		if obj.iterVar2 != "" {
			obj.operator = TransformList
		}
		obj.expr = loopStep.getArg(1).getListElement(0).e()
	case operators.Conditional:
		switch e.AccuInit.ExprKind.(type) {
		case *exprpb.Expr_ListExpr:
			if e2 := loopStep.getArg(1).getArg(1).getListElement(0).e(); e2.GetCallExpr() != nil {
				obj.expr2 = e2
				obj.operator = TransformList
			} else {
				obj.operator = Filter
			}
		case *exprpb.Expr_ConstExpr:
			obj.operator = ExistsOne
		case *exprpb.Expr_StructExpr:
			var err error
			obj.operator, obj.expr2, err = getTransformMapExpression(loopStep.getArg(1))
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("expected loop-accu-init expression type ConstExpr or ListExpr, got: %T", e.AccuInit.ExprKind)
		}
		obj.expr = loopStep.getArg(0).e()
	case "cel.@mapInsert":
		var err error
		obj.operator, obj.expr, err = getTransformMapExpression(loopStep)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected loop-step function: %q", function)
	}

	return obj, nil
}

type wrapper exprpb.Expr

func (w *wrapper) e() *exprpb.Expr {
	return (*exprpb.Expr)(w)
}

func (w *wrapper) getArg(i int) *wrapper {
	if w == nil {
		return nil
	}
	if x := w.e().GetCallExpr(); x != nil && i < len(x.Args) {
		return (*wrapper)(x.Args[i])
	}
	return nil
}

func (w *wrapper) getArgsLen() int {
	if w == nil {
		return 0
	}
	if x := w.e().GetCallExpr(); x != nil {
		return len(x.Args)
	}
	return 0
}

func (w *wrapper) getListElement(i int) *wrapper {
	if w == nil {
		return nil
	}
	if x := w.e().GetListExpr(); x != nil && i < len(x.Elements) {
		return (*wrapper)(x.Elements[i])
	}
	return nil
}
