// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"fmt"

	"github.com/google/cel-go/common/operators"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type lambdaAST struct {
	iterRange  *exprpb.Expr
	lambdaExpr *exprpb.Expr
	operator   string
	iterVar    string
}

func buildLambdaAST(e *exprpb.Expr_Comprehension) (*lambdaAST, error) {
	obj := &lambdaAST{
		iterVar:   e.IterVar,
		iterRange: e.IterRange,
	}
	var step *exprpb.Expr_CallExpr
	var ok bool
	if step, ok = e.LoopStep.ExprKind.(*exprpb.Expr_CallExpr); !ok {
		return nil, fmt.Errorf("expected loop-step expression type CallExpr, got: %T", e.LoopStep.ExprKind)
	}
	switch step.CallExpr.Function {
	case operators.LogicalAnd:
		obj.operator = All
		obj.lambdaExpr = step.CallExpr.Args[1]
	case operators.LogicalOr:
		obj.operator = Exists
		obj.lambdaExpr = step.CallExpr.Args[1]
	case operators.Add:
		obj.operator = Map
		if elements := step.CallExpr.Args[1].GetListExpr().GetElements(); len(elements) > 0 {
			obj.lambdaExpr = elements[0]
		}
	case operators.Conditional:
		switch e.AccuInit.ExprKind.(type) {
		case *exprpb.Expr_ListExpr:
			obj.operator = Filter
		case *exprpb.Expr_ConstExpr:
			obj.operator = ExistsOne
		default:
			return nil, fmt.Errorf("expected loop-accu-init expression type ConstExpr or ListExpr, got: %T", e.AccuInit.ExprKind)
		}
		obj.lambdaExpr = step.CallExpr.Args[0]
	default:
		return nil, fmt.Errorf("unexpected loop-step function: %q", step.CallExpr.Function)
	}

	return obj, nil
}
