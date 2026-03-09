// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index_test

import (
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestParentRoleIndex(t *testing.T) {
	impl := index.New()

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

	require.NoError(t, impl.IndexParentRoles(scopeParentRoles))

	t.Run("transitive closure", func(t *testing.T) {
		roles, err := impl.AddParentRoles([]string{"acme"}, []string{"manager"})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"manager", "employee", "user"}, roles)
	})

	t.Run("scope union", func(t *testing.T) {
		roles, err := impl.AddParentRoles([]string{"acme", "acme.hr"}, []string{"manager"})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"manager", "employee", "user", "contractor"}, roles)
	})

	t.Run("replace existing parent role index", func(t *testing.T) {
		require.NoError(t, impl.IndexParentRoles(map[string]*runtimev1.RuleTable_RoleParentRoles{}))

		roles, err := impl.AddParentRoles([]string{"acme", "acme.hr"}, []string{"manager"})
		require.NoError(t, err)
		require.Equal(t, []string{"manager"}, roles)
	})
}

func TestParamsIndex(t *testing.T) {
	t.Run("interns equivalent params", func(t *testing.T) {
		impl := index.New()

		ast, iss := conditions.StdEnv.Compile("1 + 1")
		require.Nil(t, iss)
		checkedExpr, err := cel.AstToCheckedExpr(ast)
		require.NoError(t, err)

		// Two separate Params proto pointers with identical content.
		// The params cache should compile CEL programs only once and share the result.
		params1 := &runtimev1.RuleTable_RuleRow_Params{
			OrderedVariables: []*runtimev1.Variable{{
				Name: "v",
				Expr: &runtimev1.Expr{Original: "1 + 1", Checked: checkedExpr},
			}},
			Constants: map[string]*structpb.Value{"k": structpb.NewStringValue("v")},
		}
		params2 := &runtimev1.RuleTable_RuleRow_Params{
			OrderedVariables: []*runtimev1.Variable{{
				Name: "v",
				Expr: &runtimev1.Expr{Original: "1 + 1", Checked: checkedExpr},
			}},
			Constants: map[string]*structpb.Value{"k": structpb.NewStringValue("v")},
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

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2)

		require.Same(t, allRows[0].Core.Params, allRows[1].Core.Params, "expected shared RowParams pointer from params interning")
	})
}

func TestFunctionalChecksum(t *testing.T) {
	t.Run("rows differing only in origin_fqn are deduplicated", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b"),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "functionally identical rows should be deduplicated")
	})

	t.Run("rows differing in condition are not deduplicated", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b", func(r *runtimev1.RuleTable_RuleRow) {
				r.Condition = &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{Original: "true"}}}
			}),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2, "rows with different conditions should not be deduplicated")
	})

	t.Run("different emit_output prevents dedup", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b", func(r *runtimev1.RuleTable_RuleRow) {
				r.EmitOutput = &runtimev1.Output{When: &runtimev1.Output_When{RuleActivated: &runtimev1.Expr{Original: "output"}}}
			}),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2, "rows with different emit_output should not be deduplicated")
	})

	t.Run("delete policy with shared row preserves row for remaining origin", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
			makeRow("policy_b"),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "rows should be deduplicated")

		// Delete policy_a — row should survive with policy_b's origin.
		require.NoError(t, impl.DeletePolicy("policy_a"))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "row should survive after deleting one origin")

		// Delete policy_b — row should be removed entirely.
		require.NoError(t, impl.DeletePolicy("policy_b"))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 0, "row should be removed after deleting last origin")
	})

	t.Run("delete policy removes orphaned binding when core is shared across different routing tuples", func(t *testing.T) {
		impl := index.New()

		// Two FQNs produce functionally identical rows (same effect, no condition)
		// but with different resources, so they get different routing tuples and
		// separate binding IDs. They share the same FunctionalCore.
		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"), // resource="document"
			makeRow("policy_b", func(r *runtimev1.RuleTable_RuleRow) {
				r.Resource = "image"
			}),
		}

		require.NoError(t, impl.IndexRules(rules))

		// Both bindings should be queryable.
		docRows := impl.Query("default", "document", "", "", nil, 0, "")
		require.Len(t, docRows, 1)

		imgRows := impl.Query("default", "image", "", "", nil, 0, "")
		require.Len(t, imgRows, 1)

		// Delete policy_a — its binding (resource="document") must be removed
		// even though the shared core still has policy_b in origins.
		require.NoError(t, impl.DeletePolicy("policy_a"))

		docRows = impl.Query("default", "document", "", "", nil, 0, "")
		require.Len(t, docRows, 0, "orphaned binding for deleted policy should be removed from dimensions")

		imgRows = impl.Query("default", "image", "", "", nil, 0, "")
		require.Len(t, imgRows, 1, "surviving policy's binding should remain")

		// Delete policy_b — everything should be clean.
		require.NoError(t, impl.DeletePolicy("policy_b"))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 0, "all bindings should be removed after deleting all origins")
	})

	t.Run("rows with params differing only in origin_fqn are deduplicated", func(t *testing.T) {
		// Uses FromRolePolicy: false with non-nil Params to exercise the params compilation path.
		// Verifies that params interning doesn't interfere with functional checksumming.
		impl := index.New()

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

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "functionally identical rows with params should be deduplicated")
		require.NotNil(t, allRows[0].Core.Params, "deduplicated row should have compiled params")
	})

	t.Run("incremental indexing merges origins across batches", func(t *testing.T) {
		impl := index.New()

		// First batch — adds row with policy_a origin.
		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow("policy_a"),
		}))

		// Second batch — same functional row from policy_b triggers updateIndex → unionAll.
		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow("policy_b"),
		}))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "incremental indexing should still deduplicate")

		// Delete one origin — row should survive.
		require.NoError(t, impl.DeletePolicy("policy_a"))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "row should survive with remaining origin")

		// Delete the remaining origin — row should be removed.
		require.NoError(t, impl.DeletePolicy("policy_b"))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 0, "row should be removed after all origins deleted")
	})
}

func TestGetVersions(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow("p1", func(r *runtimev1.RuleTable_RuleRow) { r.Version = "v1" }),
		makeRow("p2", func(r *runtimev1.RuleTable_RuleRow) { r.Version = "v2"; r.Role = "editor" }),
	}))
	require.ElementsMatch(t, []string{"v1", "v2"}, impl.GetVersions())
}

func TestGetActions(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow("p1", func(r *runtimev1.RuleTable_RuleRow) {
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}
		}),
		makeRow("p2", func(r *runtimev1.RuleTable_RuleRow) {
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "edit"}
			r.Role = "editor"
		}),
	}))
	require.ElementsMatch(t, []string{"view", "edit"}, impl.GetActions())
}

func TestGetResources(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow("p1"),
		makeRow("p2", func(r *runtimev1.RuleTable_RuleRow) { r.Resource = "image"; r.Role = "editor" }),
	}))
	require.ElementsMatch(t, []string{"document", "image"}, impl.GetResources())
}

func TestQueryMulti(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow("p1", func(r *runtimev1.RuleTable_RuleRow) {
			r.Version = "v1"
			r.Resource = "document"
			r.Role = "viewer"
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}
		}),
		makeRow("p2", func(r *runtimev1.RuleTable_RuleRow) {
			r.Version = "v1"
			r.Resource = "document"
			r.Role = "editor"
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "edit"}
		}),
		makeRow("p3", func(r *runtimev1.RuleTable_RuleRow) {
			r.Version = "v2"
			r.Resource = "image"
			r.Role = "viewer"
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}
		}),
	}))

	t.Run("all nil returns everything", func(t *testing.T) {
		res := impl.QueryMulti(nil, nil, nil, nil, nil)
		require.Len(t, res, 3)
	})

	t.Run("filter by version", func(t *testing.T) {
		res := impl.QueryMulti([]string{"v1"}, nil, nil, nil, nil)
		require.Len(t, res, 2)
		for _, b := range res {
			require.Equal(t, "v1", b.Version)
		}
	})

	t.Run("filter by multiple roles", func(t *testing.T) {
		res := impl.QueryMulti(nil, nil, nil, []string{"viewer", "editor"}, nil)
		require.Len(t, res, 3)
	})

	t.Run("filter by action", func(t *testing.T) {
		res := impl.QueryMulti(nil, nil, nil, nil, []string{"edit"})
		require.Len(t, res, 1)
		require.Equal(t, "editor", res[0].Role)
	})

	t.Run("AND across dimensions", func(t *testing.T) {
		res := impl.QueryMulti([]string{"v1"}, []string{"document"}, nil, []string{"viewer"}, []string{"view"})
		require.Len(t, res, 1)
		require.Equal(t, "viewer", res[0].Role)
		require.Equal(t, "document", res[0].Resource)
	})

	t.Run("no match returns nil", func(t *testing.T) {
		res := impl.QueryMulti([]string{"v99"}, nil, nil, nil, nil)
		require.Nil(t, res)
	})
}

func TestQueryMultiAllowActions(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow("p1", func(r *runtimev1.RuleTable_RuleRow) {
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}
		}),
		makeRow("p2", func(r *runtimev1.RuleTable_RuleRow) {
			r.Role = "admin"
			r.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
				AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
					Actions: map[string]*emptypb.Empty{"view": {}, "edit": {}},
				},
			}
		}),
	}))

	t.Run("action filter includes AllowActions bindings", func(t *testing.T) {
		res := impl.QueryMulti(nil, nil, nil, nil, []string{"view"})
		require.Len(t, res, 2)
	})

	t.Run("no action filter returns all including AllowActions", func(t *testing.T) {
		res := impl.QueryMulti(nil, nil, nil, nil, nil)
		require.Len(t, res, 2)
	})
}

func TestToRuleRow(t *testing.T) {
	impl := index.New()

	original := &runtimev1.RuleTable_RuleRow{
		OriginFqn:         "policy1",
		PolicyKind:        policyv1.Kind_KIND_RESOURCE,
		Resource:          "document",
		Role:              "viewer",
		ActionSet:         &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:            effectv1.Effect_EFFECT_ALLOW,
		Version:           "default",
		Scope:             "acme",
		OriginDerivedRole: "dr1",
		Name:              "rule1",
		Principal:         "alice",
		EvaluationKey:     "ek1",
		ScopePermissions:  policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS,
		FromRolePolicy:    true,
	}

	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{original}))
	bindings, err := impl.GetAllRows()
	require.NoError(t, err)
	require.Len(t, bindings, 1)

	row := bindings[0].ToRuleRow()
	require.Equal(t, original.OriginFqn, row.OriginFqn)
	require.Equal(t, original.Resource, row.Resource)
	require.Equal(t, original.Role, row.Role)
	require.Equal(t, original.Version, row.Version)
	require.Equal(t, original.Scope, row.Scope)
	require.Equal(t, original.Effect, row.Effect)
	require.Equal(t, original.PolicyKind, row.PolicyKind)
	require.Equal(t, original.FromRolePolicy, row.FromRolePolicy)
	require.Equal(t, original.ScopePermissions, row.ScopePermissions)
	require.Equal(t, original.OriginDerivedRole, row.OriginDerivedRole)
	require.Equal(t, original.Name, row.Name)
	require.Equal(t, original.Principal, row.Principal)
	require.Equal(t, original.EvaluationKey, row.EvaluationKey)

	actionRow, ok := row.ActionSet.(*runtimev1.RuleTable_RuleRow_Action)
	require.True(t, ok)
	require.Equal(t, "view", actionRow.Action)
}

func TestToRuleRowAllowActions(t *testing.T) {
	impl := index.New()

	original := makeRow("policy1", func(r *runtimev1.RuleTable_RuleRow) {
		r.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
			AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
				Actions: map[string]*emptypb.Empty{"view": {}, "edit": {}},
			},
		}
	})

	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{original}))
	bindings, err := impl.GetAllRows()
	require.NoError(t, err)
	require.Len(t, bindings, 1)

	row := bindings[0].ToRuleRow()
	aaRow, ok := row.ActionSet.(*runtimev1.RuleTable_RuleRow_AllowActions_)
	require.True(t, ok)
	require.Len(t, aaRow.AllowActions.Actions, 2)
	require.Contains(t, aaRow.AllowActions.Actions, "view")
	require.Contains(t, aaRow.AllowActions.Actions, "edit")
}

func makeRow(fqn string, mutators ...func(*runtimev1.RuleTable_RuleRow)) *runtimev1.RuleTable_RuleRow {
	r := &runtimev1.RuleTable_RuleRow{
		OriginFqn:  fqn,
		PolicyKind: policyv1.Kind_KIND_RESOURCE,
		Resource:   "document",
		Role:       "viewer",
		ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:     effectv1.Effect_EFFECT_ALLOW,
		Version:    "default",
		// Default to role-policy-derived rows in tests so Params can remain nil unless
		// a test explicitly opts into the params compilation path.
		FromRolePolicy: true,
	}
	for _, m := range mutators {
		m(r)
	}
	return r
}
