// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index_test

import (
	"context"
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestParentRoleIndex(t *testing.T) {
	ctx := context.Background()
	impl := index.NewImpl(index.NewMem())

	scopeParentRoles := map[string]*runtimev1.RuleTable_RoleParentRoles{
		"acme": {
			RoleParentRoles: map[string]*runtimev1.RuleTable_RoleParentRoles_ParentRoles{
				"manager": {
					Roles: []string{"employee"},
				},
				"employee": {
					Roles: []string{"user"},
				},
			},
		},
		"acme.hr": {
			RoleParentRoles: map[string]*runtimev1.RuleTable_RoleParentRoles_ParentRoles{
				"manager": {
					Roles: []string{"contractor"},
				},
			},
		},
	}

	require.NoError(t, impl.IndexParentRoles(ctx, scopeParentRoles))

	t.Run("transitive closure", func(t *testing.T) {
		roles, err := impl.AddParentRoles(ctx, []string{"acme"}, []string{"manager"})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"manager", "employee", "user"}, roles)
	})

	t.Run("scope union", func(t *testing.T) {
		roles, err := impl.AddParentRoles(ctx, []string{"acme", "acme.hr"}, []string{"manager"})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"manager", "employee", "user", "contractor"}, roles)
	})

	t.Run("replace existing parent role index", func(t *testing.T) {
		require.NoError(t, impl.IndexParentRoles(ctx, map[string]*runtimev1.RuleTable_RoleParentRoles{}))

		roles, err := impl.AddParentRoles(ctx, []string{"acme", "acme.hr"}, []string{"manager"})
		require.NoError(t, err)
		require.Equal(t, []string{"manager"}, roles)
	})
}

func TestParamsInterning(t *testing.T) {
	ctx := context.Background()
	impl := index.NewImpl(index.NewMem())

	// Two separate Params proto pointers with identical content.
	// The params cache should compile CEL programs only once and share the result.
	params1 := &runtimev1.RuleTable_RuleRow_Params{
		OrderedVariables: []*runtimev1.Variable{},
		Constants:        map[string]*structpb.Value{},
	}
	params2 := &runtimev1.RuleTable_RuleRow_Params{
		OrderedVariables: []*runtimev1.Variable{},
		Constants:        map[string]*structpb.Value{},
	}

	rules := []*runtimev1.RuleTable_RuleRow{
		{
			OriginFqn:  "policy1",
			PolicyKind: policyv1.Kind_KIND_RESOURCE,
			Resource:   "document",
			Role:       "viewer",
			ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
			Effect:     effectv1.Effect_EFFECT_ALLOW,
			Version:    "default",
			Params:     params1,
		},
		{
			OriginFqn:  "policy1",
			PolicyKind: policyv1.Kind_KIND_RESOURCE,
			Resource:   "document",
			Role:       "editor",
			ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "edit"},
			Effect:     effectv1.Effect_EFFECT_ALLOW,
			Version:    "default",
			Params:     params2,
		},
	}

	require.NoError(t, impl.IndexRules(ctx, rules))

	allRows, err := impl.GetAllRows(ctx)
	require.NoError(t, err)
	require.Len(t, allRows, 2)

	// Both rows should share the same compiled *rowParams (pointer equality)
	// because the params cache detects identical proto content.
	require.True(t, allRows[0].Params == allRows[1].Params, "expected shared rowParams pointer from params interning")
}

// makeRow builds a base RuleRow with common defaults and applies optional mutators.
func makeRow(fqn string, mutators ...func(*runtimev1.RuleTable_RuleRow)) *runtimev1.RuleTable_RuleRow {
	r := &runtimev1.RuleTable_RuleRow{
		OriginFqn:      fqn,
		PolicyKind:     policyv1.Kind_KIND_RESOURCE,
		Resource:       "document",
		Role:           "viewer",
		ActionSet:      &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:         effectv1.Effect_EFFECT_ALLOW,
		Version:        "default",
		FromRolePolicy: true,
	}
	for _, m := range mutators {
		m(r)
	}
	return r
}

func TestFunctionalChecksum(t *testing.T) {
	t.Run("rows differing only in origin_fqn are deduplicated", func(t *testing.T) {
		ctx := context.Background()
		impl := index.NewImpl(index.NewMem())

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b"),
		}

		require.NoError(t, impl.IndexRules(ctx, rules))

		allRows, err := impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 1, "functionally identical rows should be deduplicated")
	})

	t.Run("rows differing in condition are not deduplicated", func(t *testing.T) {
		ctx := context.Background()
		impl := index.NewImpl(index.NewMem())

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b", func(r *runtimev1.RuleTable_RuleRow) {
				r.Condition = &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{Original: "true"}}}
			}),
		}

		require.NoError(t, impl.IndexRules(ctx, rules))

		allRows, err := impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 2, "rows with different conditions should not be deduplicated")
	})

	t.Run("different emit_output prevents dedup", func(t *testing.T) {
		ctx := context.Background()
		impl := index.NewImpl(index.NewMem())

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b", func(r *runtimev1.RuleTable_RuleRow) {
				r.EmitOutput = &runtimev1.Output{When: &runtimev1.Output_When{RuleActivated: &runtimev1.Expr{Original: "output"}}}
			}),
		}

		require.NoError(t, impl.IndexRules(ctx, rules))

		allRows, err := impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 2, "rows with different emit_output should not be deduplicated")
	})

	t.Run("delete policy with shared row preserves row for remaining origin", func(t *testing.T) {
		ctx := context.Background()
		impl := index.NewImpl(index.NewMem())

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b"),
		}

		require.NoError(t, impl.IndexRules(ctx, rules))

		allRows, err := impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 1, "rows should be deduplicated")

		// Delete policy_a — row should survive with policy_b's origin.
		require.NoError(t, impl.DeletePolicy(ctx, "policy_a", nil))

		allRows, err = impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 1, "row should survive after deleting one origin")

		// Delete policy_b — row should be removed entirely.
		require.NoError(t, impl.DeletePolicy(ctx, "policy_b", nil))

		allRows, err = impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 0, "row should be removed after deleting last origin")
	})

	t.Run("rows with params differing only in origin_fqn are deduplicated", func(t *testing.T) {
		// Uses FromRolePolicy: false with non-nil Params to exercise the params compilation path.
		// Verifies that params interning doesn't interfere with functional checksumming.
		ctx := context.Background()
		impl := index.NewImpl(index.NewMem())

		withParams := func(r *runtimev1.RuleTable_RuleRow) {
			r.FromRolePolicy = false
			r.Params = &runtimev1.RuleTable_RuleRow_Params{
				OrderedVariables: []*runtimev1.Variable{},
				Constants:        map[string]*structpb.Value{},
			}
		}

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a", withParams),
			makeRow("policy_b", withParams),
		}

		require.NoError(t, impl.IndexRules(ctx, rules))

		allRows, err := impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 1, "functionally identical rows with params should be deduplicated")
		require.NotNil(t, allRows[0].Params, "deduplicated row should have compiled params")
	})

	t.Run("incremental indexing merges origins across batches", func(t *testing.T) {
		ctx := context.Background()
		impl := index.NewImpl(index.NewMem())

		// First batch — adds row with policy_a origin.
		require.NoError(t, impl.IndexRules(ctx, []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
		}))

		// Second batch — same functional row from policy_b triggers updateIndex → unionAll.
		require.NoError(t, impl.IndexRules(ctx, []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_b"),
		}))

		allRows, err := impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 1, "incremental indexing should still deduplicate")

		// Delete one origin — row should survive.
		require.NoError(t, impl.DeletePolicy(ctx, "policy_a", nil))

		allRows, err = impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 1, "row should survive with remaining origin")

		// Delete the remaining origin — row should be removed.
		require.NoError(t, impl.DeletePolicy(ctx, "policy_b", nil))

		allRows, err = impl.GetAllRows(ctx)
		require.NoError(t, err)
		require.Len(t, allRows, 0, "row should be removed after all origins deleted")
	})
}
