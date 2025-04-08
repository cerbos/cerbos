// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"fmt"
	"maps"
	"slices"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

func MergeWithAnd(responses []*enginev1.PlanResourcesOutput) (*enginev1.PlanResourcesFilter, string, error) {
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
			}, res.FilterDebug, nil
		case enginev1.PlanResourcesFilter_KIND_CONDITIONAL:
			conds[res.FilterDebug] = res.Filter.Condition
		case enginev1.PlanResourcesFilter_KIND_UNSPECIFIED:
			return nil, "", fmt.Errorf("unknown filter kind %s", res.Filter.Kind)
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
	return response, FilterToString(response), nil
}
