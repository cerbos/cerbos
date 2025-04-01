// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"fmt"
	"maps"
	"slices"
	"sort"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"google.golang.org/protobuf/types/known/structpb"
)

func MergeWithAnd(responses []*enginev1.PlanResourcesOutput) *enginev1.PlanResourcesFilter {
	response := &enginev1.PlanResourcesFilter{
		Kind: enginev1.PlanResourcesFilter_KIND_CONDITIONAL,
	}
	conds := make(map[string]*exprOp, len(responses))
	for _, res := range responses {
		switch res.Filter.Kind {
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED:
			continue
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED:
			return &enginev1.PlanResourcesFilter{
				Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED,
			}
		case enginev1.PlanResourcesFilter_KIND_CONDITIONAL:
			conds[res.FilterDebug] = res.Filter.Condition
		case enginev1.PlanResourcesFilter_KIND_UNSPECIFIED:
			panic(fmt.Errorf("unknown filter kind %s", res.Filter.Kind))
		}
	}
	switch len(conds) {
	case 0:
		response = &enginev1.PlanResourcesFilter{
			Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED,
		}
	case 1:
		for _, filter := range conds {
			response.Condition = filter
		}
	default:
		filters := slices.Collect(maps.Values(conds))
		response.Condition = &exprOp{Node: mkExprOpExpr(And, filters...)}
	}
	return response
}
func Merge(outputs map[string]*enginev1.PlanResourcesOutput) *enginev1.PlanResourcesFilter {
	response := &enginev1.PlanResourcesFilter{
		Kind: enginev1.PlanResourcesFilter_KIND_CONDITIONAL,
	}
	scopes := slices.Sorted(maps.Keys(outputs))
	expressions := make([]*enginev1.PlanResourcesFilter_Expression_Operand, 0, len(outputs))
	nots := make([]string, 0, len(outputs))
	conds := make(map[string][]string, len(outputs))
	for _, scope := range scopes {
		output := outputs[scope]
		switch output.Filter.Kind {
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED:
			expressions = append(expressions, mkScopeOp(Equals, scope))
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED:
			nots = append(nots, scope)
		case enginev1.PlanResourcesFilter_KIND_CONDITIONAL:
			conds[output.FilterDebug] = append(conds[output.FilterDebug], scope)
		case enginev1.PlanResourcesFilter_KIND_UNSPECIFIED:
			panic("unspecified filter kind")
		}
	}
	expressions = allowedExprs(outputs, conds, expressions)
	var or *exprOp
	if len(expressions) > 1 {
		or = &exprOp{Node: mkExprOpExpr(Or, expressions...)}
	} else if len(expressions) == 1 {
		or = expressions[0]
	}
	switch len(nots) {
	case 0:
		response.Condition = or
	case 1:
		response.Condition = mkScopeOp(NotEquals, nots[0])
		if or != nil {
			response.Condition = &exprOp{Node: mkExprOpExpr(And, or, response.Condition)}
		}
	default:
		response.Condition = &exprOp{Node: mkExprOpExpr(Not, mkScopeIn(nots))}
		if or != nil {
			response.Condition = &exprOp{
				Node: mkExprOpExpr(And,
					or,
					response.Condition,
				),
			}
		}
	}
	return response
}

func allowedExprs(outputs map[string]*enginev1.PlanResourcesOutput, conds map[string][]string, expressions []*enginev1.PlanResourcesFilter_Expression_Operand) []*enginev1.PlanResourcesFilter_Expression_Operand {
	ks := slices.Sorted(maps.Keys(conds))
	for _, k := range ks {
		ss := conds[k]
		scope := ss[0]
		c := outputs[scope].Filter.Condition
		if len(ss) > 1 {
			expressions = append(expressions, &exprOp{Node: mkExprOpExpr(And, mkScopeIn(ss), c)})
		} else {
			expressions = append(expressions, &exprOp{Node: mkExprOpExpr(And, mkScopeOp(Equals, scope), c)})
		}
	}
	return expressions
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

func mkScopeIn(scopes []string) *exprOp {
	values := make([]*structpb.Value, 0, len(scopes))
	sort.Strings(scopes)
	for _, scope := range scopes {
		values = append(values, &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: scope}})
	}
	return &exprOp{
		Node: mkExprOpExpr(In,
			mkExprOpFromVar(conditions.ResourceFqn(conditions.CELScopeField)),
			mkExprOpFromValue(structpb.NewListValue(&structpb.ListValue{Values: values}))),
	}
}
