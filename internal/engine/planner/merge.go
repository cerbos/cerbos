// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"google.golang.org/protobuf/types/known/structpb"
)

func Merge(outputs map[string]*enginev1.PlanResourcesOutput) *enginev1.PlanResourcesFilter {
	response := &enginev1.PlanResourcesFilter{
		Kind: enginev1.PlanResourcesFilter_KIND_CONDITIONAL,
	}
	expressions := make([]*enginev1.PlanResourcesFilter_Expression_Operand, 0, len(outputs))
	nots := make([]string, 0, len(outputs))
	for scope, output := range outputs {
		switch output.Filter.Kind {
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED:
			expressions = append(expressions, mkScopeOp(Equals, scope))
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED:
			nots = append(nots, scope)
		case enginev1.PlanResourcesFilter_KIND_CONDITIONAL:
			expressions = append(expressions, &exprOp{Node: mkExprOpExpr(And, mkScopeOp(Equals, scope), output.Filter.Condition)})
		}
	}
	var or *exprOp
	if len(expressions) > 1 {
		or = &exprOp{Node: mkExprOpExpr(Or, expressions...)}
	} else {
		or = expressions[0]
	}
	switch len(nots) {
	case 0:
		response.Condition = or
	case 1:
		response.Condition = &exprOp{Node: mkExprOpExpr(And, or, mkScopeOp(NotEquals, nots[0]))}
	default:
		values := make([]*structpb.Value, 0, len(nots))
		for _, scope := range nots {
			values = append(values, &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: scope}})
		}
		response.Condition = &exprOp{
			Node: mkExprOpExpr(And,
				or,
				&exprOp{
					Node: mkExprOpExpr(Not,
						&exprOp{
							Node: mkExprOpExpr(In,
								mkExprOpFromVar(conditions.ResourceFqn(conditions.CELScopeField)),
								mkExprOpFromValue(structpb.NewListValue(&structpb.ListValue{Values: values})))},
					),
				},
			),
		}
	}
	return response
}
func mkExprOpFromVar(variable string) *exprOp {
	return &exprOp{
		Node: &exprOpVar{
			Variable: variable,
		},
	}
}
func mkExprOpFromValue(value *structpb.Value) *exprOp {
	return &exprOp{
		Node: &exprOpValue{
			Value: value,
		},
	}
}
func mkScopeOp(op, scope string) *exprOp {
	return &exprOp{
		Node: mkExprOpExpr(op, mkExprOpFromVar(conditions.ResourceFqn(conditions.CELScopeField)), mkExprOpFromValue(structpb.NewStringValue(scope))),
	}
}
