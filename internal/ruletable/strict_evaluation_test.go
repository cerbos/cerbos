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
	"github.com/cerbos/cerbos/internal/evaluator"
)

func assertStrictEvaluationError(t *testing.T, err error, wantExpr string) {
	t.Helper()
	var strictErr evaluator.StrictEvaluationError
	require.Error(t, err)
	require.ErrorAs(t, err, &strictErr)
	require.Equal(t, wantExpr, strictErr.Expression)
}

func TestStrictEvaluationCheck(t *testing.T) {
	h := newCELErrorsHarness(t)
	params := h.evalParams
	params.StrictEvaluation = true

	t.Run("clean_request_succeeds", func(t *testing.T) {
		effect, entries, _ := h.check(t, params, "account", "read", structpb.NewNumberValue(5000))
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		require.Empty(t, entries)
	})

	wronglyTypedAmountValue := structpb.NewStringValue("5000")

	t.Run("erroring_deny_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInput("account", "read", wronglyTypedAmountValue))
		assertStrictEvaluationError(t, err, amountExpr)
	})

	t.Run("missing_attribute_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInput("account", "read", nil))
		assertStrictEvaluationError(t, err, amountExpr)
	})

	t.Run("erroring_allow_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInput("account", "write", wronglyTypedAmountValue))
		assertStrictEvaluationError(t, err, amountExpr)
	})

	t.Run("erroring_variable_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInput("ledger", "export", wronglyTypedAmountValue))
		assertStrictEvaluationError(t, err, amountExpr)
	})

	t.Run("erroring_derived_role_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInput("record", "view", wronglyTypedAmountValue))
		assertStrictEvaluationError(t, err, amountExpr)
	})

	t.Run("erroring_derived_role_variable_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Check(h.ctx, tracer.Start(nil), params, checkInput("wallet", "view", wronglyTypedAmountValue))
		assertStrictEvaluationError(t, err, amountExpr)
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
		require.Empty(t, entries)
	})

	t.Run("clean_request_succeeds", func(t *testing.T) {
		kind, entries := h.plan(t, params, "account", "read", structpb.NewNumberValue(5000))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		require.Empty(t, entries)
	})

	t.Run("erroring_deny_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Plan(h.ctx, params, planInput("account", "read", structpb.NewStringValue("5000")))
		assertStrictEvaluationError(t, err, amountExpr)
	})

	t.Run("erroring_allow_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Plan(h.ctx, params, planInput("account", "write", structpb.NewStringValue("5000")))
		assertStrictEvaluationError(t, err, amountExpr)
	})

	t.Run("erroring_variable_fails_request", func(t *testing.T) {
		// the planner substitutes variables into the condition, so the error is attributed to the condition expression
		_, _, err := h.mgr.Plan(h.ctx, params, planInput("ledger", "export", structpb.NewStringValue("5000")))
		assertStrictEvaluationError(t, err, "V.v1")
	})

	t.Run("erroring_derived_role_fails_request", func(t *testing.T) {
		_, _, err := h.mgr.Plan(h.ctx, params, planInput("record", "view", structpb.NewStringValue("5000")))
		assertStrictEvaluationError(t, err, amountExpr)
	})
}
