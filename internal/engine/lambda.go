// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"fmt"
	"github.com/google/cel-go/common/operators"
)

type LambdaAST struct {
	Operator   string
	IterRange  *exprpb.Expr
	IterVar    string
	LambdaExpr *exprpb.Expr
}

func BuildLambdaAST(e *exprpb.Expr_Comprehension) (*LambdaAST, error) {
	obj := &LambdaAST{
		IterVar:   e.IterVar,
		IterRange: e.IterRange,
	}
	var step *exprpb.Expr_CallExpr
	var ok bool
	if step, ok = e.LoopStep.ExprKind.(*exprpb.Expr_CallExpr); !ok {
		return nil, fmt.Errorf("expected loop-step expression type CallExpr, got: %T", e.LoopStep.ExprKind)
	}
	switch step.CallExpr.Function {
	case operators.LogicalAnd:
		obj.Operator = All
		obj.LambdaExpr = step.CallExpr.Args[1]
	case operators.LogicalOr:
		obj.Operator = Exists
		obj.LambdaExpr = step.CallExpr.Args[1]
	case operators.Add:
		obj.Operator = Map
		if elements := step.CallExpr.Args[1].GetListExpr().GetElements(); len(elements) > 0 {
			obj.LambdaExpr = elements[0]
		}
	case operators.Conditional:
		switch e.AccuInit.ExprKind.(type) {
		case *exprpb.Expr_ListExpr:
			obj.Operator = Filter
		case *exprpb.Expr_ConstExpr:
			obj.Operator = ExistsOne
		default:
			return nil, fmt.Errorf("expected loop-accu-init expression type ConstExpr or ListExpr, got: %T", e.AccuInit.ExprKind)
		}
		obj.LambdaExpr = step.CallExpr.Args[0]
	default:
		return nil, fmt.Errorf("unexpected loop-step function: %q", step.CallExpr.Function)
	}

	return obj, nil
}
