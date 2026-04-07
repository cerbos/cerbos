// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index_test

import (
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
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
		roles := impl.AddParentRoles([]string{"acme"}, []string{"manager"})
		require.ElementsMatch(t, []string{"manager", "employee", "user"}, roles)
	})

	t.Run("scope union", func(t *testing.T) {
		roles := impl.AddParentRoles([]string{"acme", "acme.hr"}, []string{"manager"})
		require.ElementsMatch(t, []string{"manager", "employee", "user", "contractor"}, roles)
	})

	t.Run("replace existing parent role index", func(t *testing.T) {
		require.NoError(t, impl.IndexParentRoles(map[string]*runtimev1.RuleTable_RoleParentRoles{}))

		roles := impl.AddParentRoles([]string{"acme", "acme.hr"}, []string{"manager"})
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

		// identical content: the params cache should compile CEL programs only once and share the result.
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

		docFQN := namer.ResourcePolicyFQN("document", "default", "")
		rules := []*runtimev1.RuleTable_RuleRow{
			{
				OriginFqn:  docFQN,
				PolicyKind: policyv1.Kind_KIND_RESOURCE,
				Resource:   "document",
				Role:       "viewer",
				ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
				Effect:     effectv1.Effect_EFFECT_ALLOW,
				Version:    "default",
				Params:     params1,
			},
			{
				OriginFqn:  docFQN,
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
	fqnA := namer.ResourcePolicyFQN("document", "default", "")
	fqnB := namer.ResourcePolicyFQN("document", "default", "acme")

	t.Run("rows differing only in origin_fqn share a FunctionalCore", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow(fqnA),
			makeRow(fqnB),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2)
		require.Same(t, allRows[0].Core, allRows[1].Core, "functionally identical rows should share a FunctionalCore")
	})

	t.Run("rows differing in condition are not deduplicated", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow(fqnA),
			makeRow(fqnB, func(r *runtimev1.RuleTable_RuleRow) {
				r.Condition = &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{Original: "true"}}}
			}),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2)
		require.NotSame(t, allRows[0].Core, allRows[1].Core, "rows with different conditions should not share a FunctionalCore")
	})

	t.Run("different emit_output prevents core sharing", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow(fqnA),
			makeRow(fqnB, func(r *runtimev1.RuleTable_RuleRow) {
				r.EmitOutput = &runtimev1.Output{When: &runtimev1.Output_When{RuleActivated: &runtimev1.Expr{Original: "output"}}}
			}),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2)
		require.NotSame(t, allRows[0].Core, allRows[1].Core, "rows with different emit_output should not share a FunctionalCore")
	})

	t.Run("delete policy removes its bindings independently", func(t *testing.T) {
		impl := index.New()

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow(fqnA),
			makeRow(fqnB),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2)

		require.NoError(t, impl.DeletePolicy(fqnA))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "only fqnB's binding should remain")

		require.NoError(t, impl.DeletePolicy(fqnB))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 0, "all bindings should be removed")
	})

	t.Run("delete policy removes orphaned binding when core is shared across different routing tuples", func(t *testing.T) {
		impl := index.New()

		// two distinct policies produce functionally identical rows (same effect, no condition)
		// but with different resources, so they get different routing tuples and separate
		// binding IDs, but share the same FunctionalCore
		docPolicyFQN := namer.ResourcePolicyFQN("document", "default", "")
		imgPolicyFQN := namer.ResourcePolicyFQN("image", "default", "")

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow(docPolicyFQN), // resource="document"
			makeRow(imgPolicyFQN, func(r *runtimev1.RuleTable_RuleRow) {
				r.Resource = "image"
			}),
		}

		require.NoError(t, impl.IndexRules(rules))

		docRows := impl.Query("default", "document", "", "", nil, 0, "", nil)
		require.Len(t, docRows, 1)

		imgRows := impl.Query("default", "image", "", "", nil, 0, "", nil)
		require.Len(t, imgRows, 1)

		// delete `docPolicyFQN`. Its "document" binding must be removed
		// even though the shared core still has `imgPolicyFQN` in origins.
		require.NoError(t, impl.DeletePolicy(docPolicyFQN))

		docRows = impl.Query("default", "document", "", "", nil, 0, "", nil)
		require.Len(t, docRows, 0, "orphaned binding for deleted policy should be removed from dimensions")

		imgRows = impl.Query("default", "image", "", "", nil, 0, "", nil)
		require.Len(t, imgRows, 1, "surviving policy's binding should remain")

		require.NoError(t, impl.DeletePolicy(imgPolicyFQN))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 0, "all bindings should be removed after deleting all origins")
	})

	t.Run("rows with params differing only in origin_fqn share core and params", func(t *testing.T) {
		// uses FromRolePolicy: false with non-nil Params to exercise the params compilation path.
		// verifies that params interning doesn't interfere with functional checksumming.
		impl := index.New()

		withParams := func(r *runtimev1.RuleTable_RuleRow) {
			r.FromRolePolicy = false
			r.Params = &runtimev1.RuleTable_RuleRow_Params{
				OrderedVariables: []*runtimev1.Variable{},
				Constants:        map[string]*structpb.Value{},
			}
		}

		rules := []*runtimev1.RuleTable_RuleRow{
			makeRow(fqnA, withParams),
			makeRow(fqnB, withParams),
		}

		require.NoError(t, impl.IndexRules(rules))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2)
		require.Same(t, allRows[0].Core, allRows[1].Core, "functionally identical rows should share a FunctionalCore")
		require.NotNil(t, allRows[0].Core.Params, "shared core should have compiled params")
	})

	t.Run("incremental indexing shares cores across batches", func(t *testing.T) {
		impl := index.New()

		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow(fqnA),
		}))

		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow(fqnB),
		}))

		allRows, err := impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 2)
		require.Same(t, allRows[0].Core, allRows[1].Core, "incremental indexing should share FunctionalCore")

		require.NoError(t, impl.DeletePolicy(fqnA))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 1, "only fqnB's binding should remain")

		require.NoError(t, impl.DeletePolicy(fqnB))

		allRows, err = impl.GetAllRows()
		require.NoError(t, err)
		require.Len(t, allRows, 0, "row should be removed after all origins deleted")
	})
}

func TestGetVersions(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow(namer.ResourcePolicyFQN("document", "v1", ""), func(r *runtimev1.RuleTable_RuleRow) { r.Version = "v1" }),
		makeRow(namer.ResourcePolicyFQN("document", "v2", ""), func(r *runtimev1.RuleTable_RuleRow) { r.Version = "v2"; r.Role = "editor" }),
	}))
	require.ElementsMatch(t, []string{"v1", "v2"}, impl.GetVersions())
}

func TestGetActions(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow(namer.ResourcePolicyFQN("document", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}
		}),
		makeRow(namer.ResourcePolicyFQN("document", "default", "acme"), func(r *runtimev1.RuleTable_RuleRow) {
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "edit"}
			r.Role = "editor"
		}),
	}))
	require.ElementsMatch(t, []string{"view", "edit"}, impl.GetActions())
}

func TestGetResources(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow(namer.ResourcePolicyFQN("document", "default", "")),
		makeRow(namer.ResourcePolicyFQN("image", "default", ""), func(r *runtimev1.RuleTable_RuleRow) { r.Resource = "image"; r.Role = "editor" }),
	}))
	require.ElementsMatch(t, []string{"document", "image"}, impl.GetResources())
}

func TestQueryMulti(t *testing.T) {
	impl := index.New()
	require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
		makeRow(namer.ResourcePolicyFQN("document", "v1", ""), func(r *runtimev1.RuleTable_RuleRow) {
			r.Version = "v1"
			r.Resource = "document"
			r.Role = "viewer"
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}
		}),
		makeRow(namer.ResourcePolicyFQN("document", "v1", "acme"), func(r *runtimev1.RuleTable_RuleRow) {
			r.Version = "v1"
			r.Resource = "document"
			r.Role = "editor"
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "edit"}
		}),
		makeRow(namer.ResourcePolicyFQN("image", "v2", ""), func(r *runtimev1.RuleTable_RuleRow) {
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
		makeRow(namer.ResourcePolicyFQN("document", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
			r.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: "view"}
		}),
		makeRow(namer.RolePolicyFQN("admin", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
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

func TestQueryAllowActionsSyntheticDeny(t *testing.T) {
	t.Run("action not in AllowActions produces synthetic DENY", func(t *testing.T) {
		impl := index.New()
		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow(namer.RolePolicyFQN("viewer", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
				r.Role = "viewer"
				r.Resource = "document"
				r.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
					AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
						Actions: map[string]*emptypb.Empty{"view": {}, "list": {}},
					},
				}
			}),
		}))

		res := impl.Query("default", "document", "", "delete", []string{"viewer"}, policyv1.Kind_KIND_RESOURCE, "", nil)
		require.Len(t, res, 1)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, res[0].Core.Effect)
		require.True(t, res[0].Core.FromRolePolicy)
		require.True(t, res[0].NoMatchForScopePermissions)
	})

	t.Run("action in AllowActions without condition produces no synthetic DENY", func(t *testing.T) {
		impl := index.New()
		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow(namer.RolePolicyFQN("viewer", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
				r.Role = "viewer"
				r.Resource = "document"
				r.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
					AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
						Actions: map[string]*emptypb.Empty{"view": {}, "list": {}},
					},
				}
			}),
		}))

		res := impl.Query("default", "document", "", "view", []string{"viewer"}, policyv1.Kind_KIND_RESOURCE, "", nil)
		require.Len(t, res, 0)
	})

	t.Run("action in AllowActions with condition produces conditional synthetic DENY", func(t *testing.T) {
		impl := index.New()
		cond := &runtimev1.Condition{
			Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{Original: "request.resource.attr.public == true"}},
		}
		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow(namer.RolePolicyFQN("viewer", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
				r.Role = "viewer"
				r.Resource = "document"
				r.Condition = cond
				r.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
					AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
						Actions: map[string]*emptypb.Empty{"view": {}},
					},
				}
			}),
		}))

		res := impl.Query("default", "document", "", "view", []string{"viewer"}, policyv1.Kind_KIND_RESOURCE, "", nil)
		require.Len(t, res, 1)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, res[0].Core.Effect)
		require.True(t, res[0].Core.FromRolePolicy)

		// condition must be inverted (wrapped in Condition_None)
		noneOp, ok := res[0].Core.Condition.Op.(*runtimev1.Condition_None)
		require.True(t, ok, "condition should be wrapped in Condition_None")
		require.Len(t, noneOp.None.Expr, 1)
		require.Equal(t, cond, noneOp.None.Expr[0])
	})

	t.Run("multiple roles with different AllowActions sets", func(t *testing.T) {
		impl := index.New()
		require.NoError(t, impl.IndexRules([]*runtimev1.RuleTable_RuleRow{
			makeRow(namer.RolePolicyFQN("viewer", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
				r.Role = "viewer"
				r.Resource = "document"
				r.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
					AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
						Actions: map[string]*emptypb.Empty{"view": {}},
					},
				}
			}),
			makeRow(namer.RolePolicyFQN("editor", "default", ""), func(r *runtimev1.RuleTable_RuleRow) {
				r.Role = "editor"
				r.Resource = "document"
				r.Effect = effectv1.Effect_EFFECT_DENY
				r.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
					AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
						Actions: map[string]*emptypb.Empty{"view": {}, "edit": {}},
					},
				}
			}),
		}))

		res := impl.Query("default", "document", "", "edit", []string{"viewer", "editor"}, policyv1.Kind_KIND_RESOURCE, "", nil)

		// only viewer should get a synthetic DENY (edit is not in viewer's AllowActions).
		// editor has edit in its AllowActions with no condition, so no synthetic DENY
		require.Len(t, res, 1)
		require.True(t, res[0].NoMatchForScopePermissions)
		require.Equal(t, "viewer", res[0].Role)
	})
}

func makeRow(fqn string, fn ...func(*runtimev1.RuleTable_RuleRow)) *runtimev1.RuleTable_RuleRow {
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
	for _, m := range fn {
		m(r)
	}
	return r
}
