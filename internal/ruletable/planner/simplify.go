// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

// simplifyLogicalExpr reduces tautologies and contradictions among equality
// predicates. A non-nil return replaces the current AND/OR node.
func simplifyLogicalExpr(operator string, operands []*enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	switch operator {
	case And:
		if hasAndContradiction(operands) {
			return falseExprOpValue
		}
	case Or:
		if hasOrTautology(operands) {
			return trueExprOpValue
		}
	}

	return nil
}

func hasAndContradiction(operands []*enginev1.PlanResourcesFilter_Expression_Operand) bool {
	flat := flattenLogical(And, operands)
	eqs := map[string]*structpb.Value{}
	var neqs []varConst

	for _, op := range flat {
		if v, val, ok := asVarConst(op, Equals); ok {
			if prev, exists := eqs[v]; exists && !proto.Equal(prev, val) {
				return true
			}
			eqs[v] = val
			continue
		}
		if v, val, ok := asVarConst(op, NotEquals); ok {
			neqs = append(neqs, varConst{variable: v, value: val})
		}
	}

	for _, ne := range neqs {
		if prev, exists := eqs[ne.variable]; exists && proto.Equal(prev, ne.value) {
			return true
		}
	}

	for _, op := range flat {
		child := asNotOperand(op)
		if child == nil {
			continue
		}
		if containsOperand(flat, op, child) {
			return true
		}
		if v, val, ok := asVarConst(child, Equals); ok {
			if prev, exists := eqs[v]; exists && proto.Equal(prev, val) {
				return true
			}
		}
	}

	return false
}

func hasOrTautology(operands []*enginev1.PlanResourcesFilter_Expression_Operand) bool {
	flat := flattenLogical(Or, operands)
	var eqs []varConst
	var neqs []varConst

	for _, op := range flat {
		if v, val, ok := asVarConst(op, Equals); ok {
			eqs = append(eqs, varConst{variable: v, value: val})
			continue
		}
		if v, val, ok := asVarConst(op, NotEquals); ok {
			neqs = append(neqs, varConst{variable: v, value: val})
		}
	}

	for _, eq := range eqs {
		for _, ne := range neqs {
			if eq.variable == ne.variable && proto.Equal(eq.value, ne.value) {
				return true
			}
		}
	}

	for _, op := range flat {
		child := asNotOperand(op)
		if child == nil {
			continue
		}
		if containsOperand(flat, op, child) {
			return true
		}
		if v, val, ok := asVarConst(child, Equals); ok {
			for _, eq := range eqs {
				if eq.variable == v && proto.Equal(eq.value, val) {
					return true
				}
			}
		}
	}

	return false
}

type varConst struct {
	value    *structpb.Value
	variable string
}

func flattenLogical(operator string, operands []*enginev1.PlanResourcesFilter_Expression_Operand) []*enginev1.PlanResourcesFilter_Expression_Operand {
	out := make([]*enginev1.PlanResourcesFilter_Expression_Operand, 0, len(operands))
	for _, op := range operands {
		if expr := op.GetExpression(); expr != nil && expr.Operator == operator {
			out = append(out, flattenLogical(operator, expr.Operands)...)
			continue
		}
		out = append(out, op)
	}
	return out
}

func asNotOperand(op *enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	expr := op.GetExpression()
	if expr == nil || expr.Operator != Not || len(expr.Operands) != 1 {
		return nil
	}
	return expr.Operands[0]
}

func asVarConst(op *enginev1.PlanResourcesFilter_Expression_Operand, operator string) (string, *structpb.Value, bool) {
	expr := op.GetExpression()
	if expr == nil || expr.Operator != operator || len(expr.Operands) != 2 {
		return "", nil, false
	}

	a, b := expr.Operands[0], expr.Operands[1]
	if v := a.GetVariable(); v != "" && b.GetValue() != nil {
		return v, b.GetValue(), true
	}
	if v := b.GetVariable(); v != "" && a.GetValue() != nil {
		return v, a.GetValue(), true
	}
	return "", nil, false
}

func containsOperand(ops []*enginev1.PlanResourcesFilter_Expression_Operand, skip, want *enginev1.PlanResourcesFilter_Expression_Operand) bool {
	for _, op := range ops {
		if op == skip {
			continue
		}
		if proto.Equal(op, want) {
			return true
		}
		if equivalentVarConst(op, want) {
			return true
		}
	}
	return false
}

func equivalentVarConst(a, b *enginev1.PlanResourcesFilter_Expression_Operand) bool {
	for _, operator := range []string{Equals, NotEquals} {
		v1, val1, ok1 := asVarConst(a, operator)
		v2, val2, ok2 := asVarConst(b, operator)
		if ok1 && ok2 && v1 == v2 && proto.Equal(val1, val2) {
			return true
		}
	}
	return false
}
