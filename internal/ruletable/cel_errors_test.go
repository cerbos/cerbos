// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

const celErrorMsg = "Error evaluating CEL expression"

const (
	amountExpr = "R.attr.amount > 1000"
	edrExpr    = `"owner" in runtime.effectiveDerivedRoles`
)

// celErrorsHarness loads policies whose conditions raise CEL runtime errors when `amount` is not a number.
type celErrorsHarness struct {
	ctx        context.Context
	mgr        *ruletable.Manager
	evalParams evaluator.EvalParams
}

func newCELErrorsHarness(t *testing.T) *celErrorsHarness {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: test.PathToDir(t, "store")})
	require.NoError(t, err)

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(t, err)

	protoRT := ruletable.NewProtoRuletable()
	require.NoError(t, ruletable.LoadPolicies(ctx, protoRT, compiler))
	require.NoError(t, ruletable.LoadSchemas(ctx, protoRT, store))

	rt, err := ruletable.NewRuleTable(protoRT)
	require.NoError(t, err)

	mgr, err := ruletable.NewRuleTableManager(rt, compiler, schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementNone)))
	require.NoError(t, err)

	conf := &evaluator.Conf{}
	conf.SetDefaults()
	evalParams := evaluator.EvalParams{
		DefaultPolicyVersion: conf.DefaultPolicyVersion,
		DefaultScope:         conf.DefaultScope,
		CELErrorLogLevel:     conf.CELErrorLogLevel,
		NowFunc:              conditions.Now(),
	}

	return &celErrorsHarness{ctx: ctx, mgr: mgr, evalParams: evalParams}
}

func (h *celErrorsHarness) paramsWithLevel(level evaluator.CELErrorLogLevel) evaluator.EvalParams {
	params := h.evalParams
	params.CELErrorLogLevel = level
	return params
}

func (h *celErrorsHarness) check(t *testing.T, params evaluator.EvalParams, kind, action string, amount *structpb.Value) (effectv1.Effect, []*enginev1.EvaluationError, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	out, _, err := h.mgr.Check(logging.ToContext(h.ctx, zap.New(core)), tracer.Start(nil), params, checkInput(kind, action, amount))
	require.NoError(t, err)
	require.Contains(t, out.Actions, action)
	return out.Actions[action].GetEffect(), out.EvaluationErrors, logs
}

func (h *celErrorsHarness) plan(t *testing.T, params evaluator.EvalParams, kind, action string, amount *structpb.Value) (enginev1.PlanResourcesFilter_Kind, []*enginev1.EvaluationError) {
	t.Helper()
	out, _, err := h.mgr.Plan(h.ctx, params, planInput(kind, action, amount))
	require.NoError(t, err)
	return out.GetFilter().GetKind(), out.EvaluationErrors
}

func checkInput(kind, action string, amount *structpb.Value) *enginev1.CheckInput {
	return checkInputActions(kind, amount, action)
}

func checkInputActions(kind string, amount *structpb.Value, actions ...string) *enginev1.CheckInput {
	attr := map[string]*structpb.Value{}
	if amount != nil {
		attr["amount"] = amount
	}
	return &enginev1.CheckInput{
		RequestId: "1",
		Resource:  &enginev1.Resource{Kind: "cel_errors." + kind, Id: "1", Attr: attr},
		Principal: &enginev1.Principal{Id: "sam", Roles: []string{"user"}},
		Actions:   actions,
	}
}

func planInput(kind, action string, amount *structpb.Value) *enginev1.PlanResourcesInput {
	attr := map[string]*structpb.Value{}
	if amount != nil {
		attr["amount"] = amount
	}
	return &enginev1.PlanResourcesInput{
		RequestId: "1",
		Actions:   []string{action},
		Principal: &enginev1.Principal{Id: "sam", Roles: []string{"user"}},
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: "cel_errors." + kind, Attr: attr},
	}
}

func assertCELErrors(t *testing.T, entries []*enginev1.EvaluationError, wantExprs ...string) {
	t.Helper()
	var exprs []string //nolint:prealloc
	for _, entry := range entries {
		exprs = append(exprs, entry.GetCelError().GetExpression())
		require.NotEmpty(t, entry.GetCelError().GetMessage())
	}
	require.ElementsMatch(t, wantExprs, exprs)
}

// assertErrorLogs ignores the once-per-process hint line, which lands in whichever test first triggers an error.
func assertErrorLogs(t *testing.T, logs *observer.ObservedLogs, wantLevel zapcore.Level, wantExprs ...string) {
	t.Helper()
	var exprs []string //nolint:prealloc
	for _, entry := range logs.FilterMessage(celErrorMsg).All() {
		require.Equal(t, wantLevel, entry.Level)
		require.NotEmpty(t, entry.ContextMap()["error"])
		exprs = append(exprs, fmt.Sprint(entry.ContextMap()["expression"]))
	}
	require.Equal(t, wantExprs, exprs)
}

func TestCELErrorsCheck(t *testing.T) {
	h := newCELErrorsHarness(t)

	t.Run("clean_number_below_threshold", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "account", "read", structpb.NewNumberValue(500))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		assertCELErrors(t, entries)
	})

	t.Run("clean_number_above_threshold", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "account", "read", structpb.NewNumberValue(5000))
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries)
	})

	t.Run("erroring_deny_fails_open_and_is_reported", func(t *testing.T) {
		effect, entries, logs := h.check(t, h.evalParams, "account", "read", structpb.NewStringValue("5000"))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect) // fail-open preserved in v0.54
		assertCELErrors(t, entries, amountExpr)
		assertErrorLogs(t, logs, zapcore.WarnLevel, amountExpr)
	})

	t.Run("missing_attribute_is_reported", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "account", "read", nil)
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_allow_is_reported", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "account", "write", structpb.NewStringValue("5000"))
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect) // allow skipped -> no match -> default deny
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_variable_is_reported", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "ledger", "export", structpb.NewStringValue("5000"))
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		// both the variable and the condition referencing the unset variable error
		assertCELErrors(t, entries, "V.v1", amountExpr)
	})

	t.Run("erroring_derived_role_is_reported", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "record", "view", structpb.NewStringValue("5000"))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		// the condition is evaluated more than once, but the identical errors are deduplicated
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_derived_role_variable_is_reported", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "wallet", "view", structpb.NewStringValue("5000"))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		// both the variable and the condition referencing the unset variable error
		assertCELErrors(t, entries, "V.dv", amountExpr)
	})

	t.Run("clean_derived_role_active", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "record", "view", structpb.NewNumberValue(5000))
		require.Equal(t, effectv1.Effect_EFFECT_DENY, effect)
		assertCELErrors(t, entries)
	})

	t.Run("clean_derived_role_inactive", func(t *testing.T) {
		effect, entries, _ := h.check(t, h.evalParams, "record", "view", structpb.NewNumberValue(500))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		assertCELErrors(t, entries)
	})

	t.Run("level_none_silences_logs_but_still_collects", func(t *testing.T) {
		effect, entries, logs := h.check(t, h.paramsWithLevel(evaluator.CELErrorLogLevelNone), "account", "read", structpb.NewStringValue("5000"))
		require.Equal(t, effectv1.Effect_EFFECT_ALLOW, effect)
		assertCELErrors(t, entries, amountExpr)
		require.Zero(t, logs.Len())
	})

	t.Run("level_error_logs_at_error", func(t *testing.T) {
		_, entries, logs := h.check(t, h.paramsWithLevel(evaluator.CELErrorLogLevelError), "account", "read", structpb.NewStringValue("5000"))
		assertCELErrors(t, entries, amountExpr)
		assertErrorLogs(t, logs, zapcore.ErrorLevel, amountExpr)
	})
}

func TestCELErrorsPlan(t *testing.T) {
	h := newCELErrorsHarness(t)

	t.Run("unknown_attribute_is_residual_without_errors", func(t *testing.T) {
		// amount is unknown at plan time, so conditions become residual filters rather than erroring
		kind, entries := h.plan(t, h.evalParams, "account", "read", nil)
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_CONDITIONAL, kind)
		assertCELErrors(t, entries)
	})

	t.Run("clean_number_above_threshold", func(t *testing.T) {
		kind, entries := h.plan(t, h.evalParams, "account", "read", structpb.NewNumberValue(5000))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries)
	})

	t.Run("erroring_deny_fails_open_and_is_reported", func(t *testing.T) {
		kind, entries := h.plan(t, h.evalParams, "account", "read", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED, kind) // fail-open: deny dropped from the filter
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_allow_is_reported", func(t *testing.T) {
		kind, entries := h.plan(t, h.evalParams, "account", "write", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("erroring_variable_is_reported", func(t *testing.T) {
		// the planner substitutes variables into the condition, so the error is attributed to the condition expression
		kind, entries := h.plan(t, h.evalParams, "ledger", "export", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries, "V.v1")
	})

	t.Run("erroring_derived_role_is_reported", func(t *testing.T) {
		kind, entries := h.plan(t, h.evalParams, "record", "view", structpb.NewStringValue("5000"))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED, kind)
		assertCELErrors(t, entries, amountExpr)
	})

	t.Run("clean_derived_role_inactive", func(t *testing.T) {
		kind, entries := h.plan(t, h.evalParams, "record", "view", structpb.NewNumberValue(500))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED, kind)
		assertCELErrors(t, entries)
	})

	t.Run("clean_derived_role_active", func(t *testing.T) {
		kind, entries := h.plan(t, h.evalParams, "record", "view", structpb.NewNumberValue(5000))
		require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, kind)
		assertCELErrors(t, entries)
	})
}
