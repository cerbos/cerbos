// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
)

func TestPlanRoleFilters(t *testing.T) {
	resource := scopedResourcePolicy("session", "", unspecifiedPerm)
	resource.GetResourcePolicy().Rules = []*policyv1.ResourceRule{
		{Actions: []string{"view", "read"}, Roles: []string{"data_access", "admin"}, Effect: effectv1.Effect_EFFECT_ALLOW},
		{Actions: []string{"read"}, Roles: []string{"data_access"}, Effect: effectv1.Effect_EFFECT_DENY, Condition: &policyv1.Condition{
			Condition: &policyv1.Condition_Match{Match: &policyv1.Match{Op: &policyv1.Match_Expr{Expr: "R.attr.blocked"}}},
		}},
	}
	sets := make([]*runtimev1.RunnablePolicySet, 1, 4)
	sets[0] = compilePolicy(t, resource)
	for _, group := range []struct{ role, id, topology string }{
		{"group_a", "s1", "core"},
		{"group_b", "s2", "metro"},
		{"group_c", "s1", "core"},
	} {
		source := fmt.Sprintf(`apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: %s
  version: default
  scope: tenant_a.data
  parentRoles: [data_access]
  constants:
    local:
      objectIds: [%q, "unused"]
      topologies: [%q, "unused"]
  rules:
    - resource: "*"
      allowActions: ["*"]
      condition:
        match:
          all:
            of:
              - expr: R.attr.objectId in C.objectIds
              - expr: R.attr.topology in C.topologies
`, group.role, group.id, group.topology)
		p, _, err := policy.ReadPolicy(strings.NewReader(source))
		require.NoError(t, err)
		sets = append(sets, compilePolicy(t, p))
	}
	loader := staticLoader{sets: sets}
	rt, err := ruletable.NewRuleTableFromLoader(t.Context(), loader)
	require.NoError(t, err)
	mgr, err := ruletable.NewRuleTableManager(rt, loader, schema.NewNopManager())
	require.NoError(t, err)
	params := evaluator.EvalParams{DefaultPolicyVersion: "default", LenientScopeSearch: true, NowFunc: conditions.Now()}

	t.Run("different grants stay in separate branches", func(t *testing.T) {
		filters := make([]*enginev1.PlanResourcesFilter, 0, 4)
		for _, roles := range [][]string{{"group_a"}, {"group_b"}, {"group_a", "group_b"}, {"group_a", "group_c"}} {
			out, _, err := mgr.Plan(t.Context(), params, &enginev1.PlanResourcesInput{
				Principal: &enginev1.Principal{Id: "alice", Roles: roles},
				Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "session", Scope: "tenant_a.data"},
				Actions:   []string{"view"},
			})
			require.NoError(t, err)
			require.Equal(t, enginev1.PlanResourcesFilter_KIND_CONDITIONAL, out.Filter.Kind)
			filters = append(filters, out.Filter)
		}
		combined := filters[2].Condition.GetExpression()
		require.Equal(t, "or", combined.Operator)
		require.Len(t, combined.Operands, 2)
		require.True(t, proto.Equal(filters[0].Condition, combined.Operands[0]))
		require.True(t, proto.Equal(filters[1].Condition, combined.Operands[1]))
		require.True(t, proto.Equal(filters[0], filters[3]), "equivalent grants were not deduplicated")
	})

	t.Run("unconditional allow clears conditional denies", func(t *testing.T) {
		for _, roles := range [][]string{{"group_a", "admin"}, {"admin", "group_a"}} {
			out, _, err := mgr.Plan(t.Context(), params, &enginev1.PlanResourcesInput{
				Principal: &enginev1.Principal{Id: "alice", Roles: roles},
				Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "session", Scope: "tenant_a.data"},
				Actions:   []string{"read"},
			})
			require.NoError(t, err)
			require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED, out.Filter.Kind)
		}
	})

	for _, strict := range []bool{false, true} {
		params.StrictEvaluation = strict
		for _, tc := range []struct {
			name         string
			roles        []string
			id, topology string
			actions      []string
			blocked      bool
			allow        bool
		}{
			{name: "first group", roles: []string{"group_a", "group_b"}, id: "s1", topology: "core", actions: []string{"view"}, allow: true},
			{name: "last group", roles: []string{"group_a", "group_b"}, id: "s2", topology: "metro", actions: []string{"view"}, allow: true},
			{name: "mixed group selections", roles: []string{"group_a", "group_b"}, id: "s1", topology: "metro", actions: []string{"view"}},
			{name: "missing group", roles: []string{"group_a"}, id: "s2", topology: "metro", actions: []string{"view"}},
			{name: "conditional deny", roles: []string{"group_a", "group_b"}, id: "s1", topology: "core", actions: []string{"view", "read"}, blocked: true},
			{name: "multiple actions", roles: []string{"group_a", "group_b"}, id: "s1", topology: "core", actions: []string{"view", "read"}, allow: true},
			{name: "unconditional allow last", roles: []string{"group_a", "admin"}, id: "outside", topology: "outside", actions: []string{"read"}, blocked: true, allow: true},
			{name: "unconditional allow first", roles: []string{"admin", "group_a"}, id: "outside", topology: "outside", actions: []string{"read"}, blocked: true, allow: true},
		} {
			t.Run(fmt.Sprintf("%s/strict=%t", tc.name, strict), func(t *testing.T) {
				attrs := map[string]*structpb.Value{
					"objectId": structpb.NewStringValue(tc.id),
					"topology": structpb.NewStringValue(tc.topology),
					"blocked":  structpb.NewBoolValue(tc.blocked),
				}
				principal := &enginev1.Principal{Id: "alice", Roles: tc.roles}
				out, _, err := mgr.Plan(t.Context(), params, &enginev1.PlanResourcesInput{
					Principal: principal,
					Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "session", Scope: "tenant_a.data", Attr: attrs},
					Actions:   tc.actions,
				})
				require.NoError(t, err)
				want := enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED
				if tc.allow {
					want = enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED
				}
				require.Equal(t, want, out.Filter.Kind)
				checked, _, err := mgr.Check(t.Context(), tracer.Start(nil), params, &enginev1.CheckInput{
					Principal: principal,
					Resource:  &enginev1.Resource{Kind: "session", Scope: "tenant_a.data", Id: "one", Attr: attrs},
					Actions:   tc.actions,
				})
				require.NoError(t, err)
				allAllowed := true
				for _, action := range tc.actions {
					allAllowed = allAllowed && checked.Actions[action].GetEffect() == effectv1.Effect_EFFECT_ALLOW
				}
				require.Equal(t, tc.allow, allAllowed)
			})
		}
	}
}

func TestPlanManyRoles(t *testing.T) {
	const numRoles = 50
	sets := make([]*runtimev1.RunnablePolicySet, 1, numRoles+1)
	sets[0] = compilePolicy(t, scopedResourcePolicy("many_roles", "", unspecifiedPerm))
	roles := make([]string, numRoles)
	for i := range roles {
		roles[i] = fmt.Sprintf("group_%d", i)
		p := &policyv1.Policy{ApiVersion: "api.cerbos.dev/v1", PolicyType: &policyv1.Policy_RolePolicy{RolePolicy: &policyv1.RolePolicy{
			PolicyType: &policyv1.RolePolicy_Role{Role: roles[i]}, Version: "default", Scope: "tenant", ParentRoles: []string{"user"},
			Rules: []*policyv1.RoleRule{{Resource: "*", AllowActions: []string{"view"}, Condition: &policyv1.Condition{
				Condition: &policyv1.Condition_Match{Match: &policyv1.Match{Op: &policyv1.Match_Expr{Expr: fmt.Sprintf("R.attr.group == %d", i)}}},
			}}},
		}}}
		sets = append(sets, compilePolicy(t, p))
	}
	loader := staticLoader{sets: sets}
	rt, err := ruletable.NewRuleTableFromLoader(t.Context(), loader)
	require.NoError(t, err)
	mgr, err := ruletable.NewRuleTableManager(rt, loader, schema.NewNopManager())
	require.NoError(t, err)
	params := evaluator.EvalParams{DefaultPolicyVersion: "default", LenientScopeSearch: true, NowFunc: conditions.Now()}
	out, _, err := mgr.Plan(t.Context(), params, &enginev1.PlanResourcesInput{
		Principal: &enginev1.Principal{Id: "alice", Roles: roles},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "many_roles", Scope: "tenant"},
		Actions:   []string{"view"},
	})
	require.NoError(t, err)
	require.Equal(t, enginev1.PlanResourcesFilter_KIND_CONDITIONAL, out.Filter.Kind)
	require.Equal(t, "or", out.Filter.Condition.GetExpression().Operator)
	require.Len(t, out.Filter.Condition.GetExpression().Operands, numRoles)
}
