// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

func TestMergeWithAnd(t *testing.T) {
	allowed := &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED}
	denied := &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED}
	a := &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_CONDITIONAL, Condition: &exprOp{Node: &exprOpVar{Variable: "a"}}}
	z := &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_CONDITIONAL, Condition: &exprOp{Node: &exprOpVar{Variable: "z"}}}
	for _, tc := range []struct {
		name    string
		filters []*enginev1.PlanResourcesFilter
		want    string
	}{
		{name: "empty", want: "(true)"},
		{name: "allowed", filters: []*enginev1.PlanResourcesFilter{allowed}, want: "(true)"},
		{name: "single condition", filters: []*enginev1.PlanResourcesFilter{z}, want: "z"},
		{name: "condition and allowed", filters: []*enginev1.PlanResourcesFilter{allowed, z}, want: "z"},
		{name: "duplicate condition", filters: []*enginev1.PlanResourcesFilter{z, proto.Clone(z).(*enginev1.PlanResourcesFilter)}, want: "z"},
		{name: "sorted conditions", filters: []*enginev1.PlanResourcesFilter{z, allowed, a, z}, want: "(and a z)"},
		{name: "denied", filters: []*enginev1.PlanResourcesFilter{z, denied, a}, want: "(false)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := make([]*enginev1.PlanResourcesFilter, len(tc.filters))
			for i, filter := range tc.filters {
				original[i] = proto.Clone(filter).(*enginev1.PlanResourcesFilter)
			}
			filter, debug, err := MergeWithAnd(tc.filters)
			require.NoError(t, err)
			require.Equal(t, tc.want, debug)
			require.Equal(t, FilterToString(filter), debug)
			for i := range tc.filters {
				require.True(t, proto.Equal(original[i], tc.filters[i]), "merge changed an input")
			}
		})
	}

	t.Run("unspecified kind", func(t *testing.T) {
		_, _, err := MergeWithAnd([]*enginev1.PlanResourcesFilter{{}})
		require.Error(t, err)
	})
}
