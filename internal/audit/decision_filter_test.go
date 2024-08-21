// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestDecisionLogEntryFilter(t *testing.T) {
	testCases := []struct {
		name    string
		filters DecisionLogFilters
		input   *auditv1.DecisionLogEntry
		want    *auditv1.DecisionLogEntry
	}{
		{
			name:    "CheckResources/NoFilter",
			filters: DecisionLogFilters{},
			input:   mkCheckResourcesLogEntry(false),
			want:    mkCheckResourcesLogEntry(false),
		},
		{
			name: "CheckResources/OnlyDenyResponses/NoDenies",
			filters: DecisionLogFilters{
				CheckResources: CheckResourcesFilter{
					IgnoreAllowAll: true,
				},
			},
			input: mkCheckResourcesLogEntry(false),
		},
		{
			name: "CheckResources/OnlyDenyResponses/SomeDenies",
			filters: DecisionLogFilters{
				CheckResources: CheckResourcesFilter{
					IgnoreAllowAll: true,
				},
			},
			input: mkCheckResourcesLogEntry(true),
			want:  mkCheckResourcesLogEntry(true),
		},
		{
			name:    "PlanResources/NoFilter",
			filters: DecisionLogFilters{},
			input:   mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED),
			want:    mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED),
		},
		{
			name: "PlanResources/IgnoreAll",
			filters: DecisionLogFilters{
				PlanResources: PlanResourcesFilter{
					IgnoreAll: true,
				},
			},
			input: mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_CONDITIONAL),
		},
		{
			name: "PlanResources/IgnoreAlwaysAllow/AlwaysAllowed",
			filters: DecisionLogFilters{
				PlanResources: PlanResourcesFilter{
					IgnoreAlwaysAllow: true,
				},
			},
			input: mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED),
		},
		{
			name: "PlanResources/IgnoreAlwaysAllow/AlwaysDenied",
			filters: DecisionLogFilters{
				PlanResources: PlanResourcesFilter{
					IgnoreAlwaysAllow: true,
				},
			},
			input: mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED),
			want:  mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED),
		},
		{
			name: "PlanResources/IgnoreAlwaysAllow/Conditional",
			filters: DecisionLogFilters{
				PlanResources: PlanResourcesFilter{
					IgnoreAlwaysAllow: true,
				},
			},
			input: mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_CONDITIONAL),
			want:  mkPlanResourcesLogEntry(enginev1.PlanResourcesFilter_KIND_CONDITIONAL),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewDecisionLogEntryFilterFromConf(&Conf{
				confHolder: confHolder{DecisionLogFilters: tc.filters},
			})

			have := f(tc.input)
			require.Empty(t, cmp.Diff(tc.want, have, protocmp.Transform()))
		})
	}
}

func mkCheckResourcesLogEntry(includeDeny bool) *auditv1.DecisionLogEntry {
	outputs := []*enginev1.CheckOutput{
		{
			RequestId:  "test",
			ResourceId: "test",
			Actions: map[string]*enginev1.CheckOutput_ActionEffect{
				"a1": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
				"a2": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
			},
		},
	}

	if includeDeny {
		outputs[0].Actions["a2"].Effect = effectv1.Effect_EFFECT_DENY
	}

	return &auditv1.DecisionLogEntry{
		CallId: "foo",
		Method: &auditv1.DecisionLogEntry_CheckResources_{
			CheckResources: &auditv1.DecisionLogEntry_CheckResources{
				Inputs: []*enginev1.CheckInput{
					{
						RequestId: "test",
						Resource: &enginev1.Resource{
							Kind: "test:kind",
							Id:   "test",
						},
						Principal: &enginev1.Principal{
							Id:    "test",
							Roles: []string{"a", "b"},
						},
						Actions: []string{"a1", "a2"},
					},
				},
				Outputs: outputs,
			},
		},
	}
}

func mkPlanResourcesLogEntry(kind enginev1.PlanResourcesFilter_Kind) *auditv1.DecisionLogEntry {
	return &auditv1.DecisionLogEntry{
		CallId: "foo",
		Method: &auditv1.DecisionLogEntry_PlanResources_{
			PlanResources: &auditv1.DecisionLogEntry_PlanResources{
				Input: &enginev1.PlanResourcesInput{
					RequestId: "test",
					Action:    "view",
					Principal: &enginev1.Principal{
						Id: "george",
					},
					Resource: &enginev1.PlanResourcesInput_Resource{
						Kind: "leave_request",
					},
				},
				Output: &enginev1.PlanResourcesOutput{
					RequestId: "test",
					Action:    "view",
					Kind:      "leave_request",
					Filter: &enginev1.PlanResourcesFilter{
						Kind: kind,
					},
				},
			},
		},
	}
}
