// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
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

func buildLambdaAST(e *exprpb.Expr_Comprehension) (*lambdaAST, error) {
	obj := &lambdaAST{
		iterVar:   e.IterVar,
		iterVar2:  e.IterVar2,
		iterRange: e.IterRange,
	}
	var function string
	var loopStep *wrapper
	if call := e.LoopStep.GetCallExpr(); call != nil {
		function = call.Function
		loopStep = (*wrapper)(e.LoopStep)
	} else {
		return nil, fmt.Errorf("expected loop-step expression type CallExpr, got: %T", e.LoopStep.ExprKind)
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
			e2 := loopStep.getArg(1).e()
			if args := e2.GetCallExpr().GetArgs(); len(args) == 2 {
				obj.operator = TransformMapEntry
				obj.expr2 = args[1]
			} else {
				obj.operator = TransformMap
				obj.expr2 = args[2]
			}
		default:
			return nil, fmt.Errorf("expected loop-accu-init expression type ConstExpr or ListExpr, got: %T", e.AccuInit.ExprKind)
		}
		obj.expr = loopStep.getArg(0).e()
	case "cel.@mapInsert":
		if len(loopStep.e().GetCallExpr().GetArgs()) == 2 {
			obj.operator = TransformMapEntry
			obj.expr = loopStep.getArg(1).e()
		} else {
			obj.operator = TransformMap
			obj.expr = loopStep.getArg(2).e()
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
	x := w.e().GetCallExpr()
	if x != nil && i < len(x.Args) {
		return (*wrapper)(x.Args[i])
	}
	return nil
}
func (w *wrapper) getListElement(i int) *wrapper {
	if w == nil {
		return nil
	}
	x := w.e().GetListExpr()
	if x != nil && i < len(x.Elements) {
		return (*wrapper)(x.Elements[i])
	}
	return nil
}
