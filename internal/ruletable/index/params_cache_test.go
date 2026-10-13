// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"testing"

	"github.com/stretchr/testify/require"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

func mkParamsRow(fqn string, fn ...func(*runtimev1.RuleTable_RuleRow)) *runtimev1.RuleTable_RuleRow {
	r := &runtimev1.RuleTable_RuleRow{
		OriginFqn:  fqn,
		PolicyKind: policyv1.Kind_KIND_RESOURCE,
		Resource:   "document",
		Role:       "viewer",
		ActionSet:  &runtimev1.RuleTable_RuleRow_Action{Action: "view"},
		Effect:     effectv1.Effect_EFFECT_ALLOW,
		Version:    "default",
		Params: &runtimev1.RuleTable_RuleRow_Params{
			OrderedVariables: []*runtimev1.Variable{{
				Name: "v",
				Expr: &runtimev1.Expr{Original: "1 + 1"},
			}},
		},
	}
	for _, m := range fn {
		m(r)
	}
	return r
}

func TestParamsCacheEviction(t *testing.T) {
	fqnA := namer.ResourcePolicyFQN("document", "default", "")
	fqnB := namer.ResourcePolicyFQN("document", "default", "acme")

	t.Run("entry evicted when the last core referencing it is deleted", func(t *testing.T) {
		impl := New()

		require.NoError(t, impl.IndexRule(mkParamsRow(fqnA)))
		require.NoError(t, impl.IndexRule(mkParamsRow(fqnA, func(r *runtimev1.RuleTable_RuleRow) {
			r.Role = "editor"
		})))
		// same params content, different conditions: two cores sharing one cache entry.
		require.NoError(t, impl.IndexRule(mkParamsRow(fqnB, func(r *runtimev1.RuleTable_RuleRow) {
			r.Condition = &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: &runtimev1.Expr{Original: "true"}}}
		})))

		require.Len(t, impl.bi.bindings, 3)
		require.Len(t, impl.paramsCache, 1)
		require.Len(t, impl.bi.coresBySum, 2)

		require.NoError(t, impl.DeletePolicy(fqnA))
		require.Len(t, impl.paramsCache, 1, "entry still referenced by fqnB's core must survive")

		require.NoError(t, impl.DeletePolicy(fqnB))
		require.Empty(t, impl.paramsCache, "entry must be evicted with its last core")
		require.Empty(t, impl.bi.coresBySum)

		// re-indexing equivalent content recompiles and repopulates the cache.
		require.NoError(t, impl.IndexRule(mkParamsRow(fqnA)))
		require.Len(t, impl.paramsCache, 1)
	})

	t.Run("no decrement while a shared core still has origins", func(t *testing.T) {
		impl := New()

		// functionally identical rows: one core with two origins.
		require.NoError(t, impl.IndexRule(mkParamsRow(fqnA)))
		require.NoError(t, impl.IndexRule(mkParamsRow(fqnB)))
		require.Len(t, impl.bi.coresBySum, 1)
		require.Len(t, impl.paramsCache, 1)

		require.NoError(t, impl.DeletePolicy(fqnA))
		require.Len(t, impl.paramsCache, 1, "core still has an origin; entry must survive")

		require.NoError(t, impl.DeletePolicy(fqnB))
		require.Empty(t, impl.paramsCache)
	})

	t.Run("derived-role params evicted alongside rule params", func(t *testing.T) {
		impl := New()

		withDR := func(r *runtimev1.RuleTable_RuleRow) {
			r.OriginDerivedRole = "owner"
			r.DerivedRoleParams = &runtimev1.RuleTable_RuleRow_Params{
				OrderedVariables: []*runtimev1.Variable{{
					Name: "d",
					Expr: &runtimev1.Expr{Original: "2 + 2"},
				}},
			}
		}
		require.NoError(t, impl.IndexRule(mkParamsRow(fqnA, withDR)))
		require.Len(t, impl.paramsCache, 1)
		require.Len(t, impl.drParamsCache, 1)

		require.NoError(t, impl.DeletePolicy(fqnA))
		require.Empty(t, impl.paramsCache)
		require.Empty(t, impl.drParamsCache)
	})
}
