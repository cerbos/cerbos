// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"fmt"
	"maps"
	"slices"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

func MergeWithAnd(filters []*enginev1.PlanResourcesFilter) (*enginev1.PlanResourcesFilter, string, error) {
	conds := make(map[string]*exprOp, len(filters))
	for _, f := range filters {
		switch f.Kind {
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED:
			continue
		case enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED:
			return &enginev1.PlanResourcesFilter{
				Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED,
			}, filterToString(f), nil
		case enginev1.PlanResourcesFilter_KIND_CONDITIONAL:
			conds[filterToString(f)] = f.Condition
		case enginev1.PlanResourcesFilter_KIND_UNSPECIFIED:
			return nil, "", fmt.Errorf("unknown filter kind %s", f.Kind)
		}
	}
	response := new(enginev1.PlanResourcesFilter)
	switch len(conds) {
	case 0:
		response.Kind = enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED
	case 1:
		for _, filter := range conds {
			response.Condition = filter
		}
		response.Kind = enginev1.PlanResourcesFilter_KIND_CONDITIONAL
	default:
		operands := make([]*exprOp, 0, len(conds))
		for _, key := range slices.Sorted(maps.Keys(conds)) {
			operands = append(operands, conds[key])
		}
		response.Condition = &exprOp{Node: mkExprOpExpr(And, operands...)}
		response.Kind = enginev1.PlanResourcesFilter_KIND_CONDITIONAL
	}
	return response, filterToString(response), nil
}
