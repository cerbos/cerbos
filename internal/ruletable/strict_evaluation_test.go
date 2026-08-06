// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
)

func TestStrictEvaluationCheck(t *testing.T) {
	h := newCELErrorsHarness(t)
	params := h.evalParams
	params.StrictEvaluation = true

	t.Run("clean_request_allows", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "account", "read", structpb.NewNumberValue(500))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		assertCELErrors(t, entries)
	})
	t.Run("clean_request_denies", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "account", "read", structpb.NewNumberValue(5000))
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries)
	})

	wronglyTypedAmountValue := structpb.NewStringValue("5000")

	t.Run("erroring_deny_denies_action", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "account", "read", wronglyTypedAmountValue)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("missing_attribute_denies_action", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "account", "read", nil)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_allow_denies_action", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "account", "write", wronglyTypedAmountValue)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_variable_denies_referencing_action_only", func(t *testing.T) {
		// the erroring variable is left unset: it denies `export`, whose condition references it,
		// but not `view`, which has no condition
		out, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInputActions("ledger", wronglyTypedAmountValue, "export", "view"))
		require.NoError(t, err)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, out.Actions["export"].GetEffect())
		require.Equal(t, "resource.ledger.vdefault", out.Actions["export"].GetPolicy())
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, out.Actions["view"].GetEffect())
		assertCELErrors(t, out.EvaluationErrors, "V.v1", amountExpr)
	})

	t.Run("erroring_derived_role_denies_action", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "record", "view", wronglyTypedAmountValue)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_derived_role_denies_referencing_actions_only", func(t *testing.T) {
		// `view` references the erroring derived role via derivedRoles, `export` accesses
		// runtime.effectiveDerivedRoles in its condition, `list` references neither
		out, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInputActions("record", wronglyTypedAmountValue, "view", "list", "export"))
		require.NoError(t, err)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, out.Actions["view"].GetEffect())
		require.Equal(t, effectv1.Effect_EFFECT_DENY, out.Actions["export"].GetEffect())
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, out.Actions["list"].GetEffect())
		assertCELErrors(t, out.EvaluationErrors, edrExpr, amountExpr)
	})

	t.Run("clean_derived_role_runtime_access_allows", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "record", "export", structpb.NewNumberValue(5000))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		assertCELErrors(t, entries)
	})

	t.Run("erroring_derived_role_variable_denies_action", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "wallet", "view", wronglyTypedAmountValue)
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries, "V.dv", amountExpr)
	})
}

func TestStrictEvaluationPlan(t *testing.T) {
	h := newCELErrorsHarness(t)
	params := h.evalParams
	params.StrictEvaluation = true

	t.Run("unknown_attribute_stays_conditional", func(t *testing.T) {
		// amount is unknown at plan time, so conditions become a filter
		kind, entries := h.plan(t, params, "account", "read", nil)
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_CONDITIONAL, kind)
		assertCELErrors(t, entries)
	})

	t.Run("clean_request_succeeds", func(t *testing.T) {
		kind, entries := h.plan(t, params, "account", "read", structpb.NewNumberValue(5000))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries)
	})

	t.Run("erroring_deny_denies_action", func(t *testing.T) {
		kind, entries := h.plan(t, params, "account", "read", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_allow_denies_action", func(t *testing.T) {
		kind, entries := h.plan(t, params, "account", "write", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_variable_denies_action", func(t *testing.T) {
		// the planner substitutes variables into the condition, so the error is attributed to the condition expression
		kind, entries := h.plan(t, params, "ledger", "export", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries, "V.v1")
	})

	t.Run("erroring_derived_role_denies_action", func(t *testing.T) {
		kind, entries := h.plan(t, params, "record", "view", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries, amountExpr)
	})
}
