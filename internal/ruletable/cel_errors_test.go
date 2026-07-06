// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
)

const celErrorMsg = "Error evaluating CEL expression"

const amountExpr = "request.resource.attr.amount > 1000"

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

	memFsys := afero.NewMemMapFs()
	idx, err := index.Build(ctx, afero.NewIOFS(memFsys))
	require.NoError(t, err)

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	subMgr := storage.NewSubscriptionManager(ctx)
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementNone))
	compiler, err := compile.NewManager(ctx, store)
	require.NoError(t, err)
	ruleTable, err := ruletable.NewRuleTable(ruletable.NewProtoRuletable())
	require.NoError(t, err)
	mgr, err := ruletable.NewRuleTableManager(ruleTable, compiler, schemaMgr)
	require.NoError(t, err)
	subMgr.Subscribe(mgr)

	cond := func(expr string) *policyv1.Condition {
		return &policyv1.Condition{
			Condition: &policyv1.Condition_Match{
				Match: &policyv1.Match{Op: &policyv1.Match_Expr{Expr: expr}},
			},
		}
	}

	drPolicy := &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_DerivedRoles{
			DerivedRoles: &policyv1.DerivedRoles{
				Name: "common_roles",
				Definitions: []*policyv1.RoleDef{
					{Name: "owner", ParentRoles: []string{"user"}, Condition: cond(amountExpr)},
				},
			},
		},
	}
	addOrUpdatePolicy(t, "derived_roles/common_roles.yaml", drPolicy, memFsys, idx, subMgr)

	// Each scenario lives in its own policy: policy-level variables and imported derived roles
	// are evaluated for every action, which would cross-pollute the expected errors.
	accountPolicy := &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource: "account",
				Version:  "default",
				Rules: []*policyv1.ResourceRule{
					{Actions: []string{"read"}, Roles: []string{"user"}, Effect: effectv1.Effect_EFFECT_ALLOW},
					{Actions: []string{"read"}, Roles: []string{"user"}, Effect: effectv1.Effect_EFFECT_DENY, Condition: cond(amountExpr)},
					{Actions: []string{"write"}, Roles: []string{"user"}, Effect: effectv1.Effect_EFFECT_ALLOW, Condition: cond(amountExpr)},
				},
			},
		},
	}
	addOrUpdatePolicy(t, "resource_policies/account.yaml", accountPolicy, memFsys, idx, subMgr)

	ledgerPolicy := &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource:  "ledger",
				Version:   "default",
				Variables: &policyv1.Variables{Local: map[string]string{"v1": amountExpr}},
				Rules: []*policyv1.ResourceRule{
					{Actions: []string{"export"}, Roles: []string{"user"}, Effect: effectv1.Effect_EFFECT_ALLOW, Condition: cond("V.v1")},
				},
			},
		},
	}
	addOrUpdatePolicy(t, "resource_policies/ledger.yaml", ledgerPolicy, memFsys, idx, subMgr)

	recordPolicy := &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource:           "record",
				Version:            "default",
				ImportDerivedRoles: []string{"common_roles"},
				Rules: []*policyv1.ResourceRule{
					{Actions: []string{"view"}, Roles: []string{"user"}, Effect: effectv1.Effect_EFFECT_ALLOW},
					{Actions: []string{"view"}, DerivedRoles: []string{"owner"}, Effect: effectv1.Effect_EFFECT_DENY},
				},
			},
		},
	}
	addOrUpdatePolicy(t, "resource_policies/record.yaml", recordPolicy, memFsys, idx, subMgr)

	conf := &evaluator.Conf{}
	conf.SetDefaults()
	evalParams := evaluator.EvalParams{
		DefaultPolicyVersion: conf.DefaultPolicyVersion,
		DefaultScope:         conf.DefaultScope,
		CELErrorLogLevel:     conf.CELErrorLogLevel,
		NowFunc:              conditions.Now(),
	}

	h := &celErrorsHarness{ctx: ctx, mgr: mgr, evalParams: evalParams}

	// Wait for the policies to load before running single-shot checks.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		read, _, err := mgr.Check(ctx, tracer.Start(nil), evalParams, checkInput("account", "read", structpb.NewNumberValue(500)))
		require.NoError(c, err)
		require.Equal(c, effectv1.Effect_EFFECT_ALLOW, read.Actions["read"].GetEffect())
		export, _, err := mgr.Check(ctx, tracer.Start(nil), evalParams, checkInput("ledger", "export", structpb.NewNumberValue(5000)))
		require.NoError(c, err)
		require.Equal(c, effectv1.Effect_EFFECT_ALLOW, export.Actions["export"].GetEffect())
		view, _, err := mgr.Check(ctx, tracer.Start(nil), evalParams, checkInput("record", "view", structpb.NewNumberValue(5000)))
		require.NoError(c, err)
		require.Equal(c, effectv1.Effect_EFFECT_DENY, view.Actions["view"].GetEffect())
	}, 5*time.Second, 50*time.Millisecond)

	return h
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
	attr := map[string]*structpb.Value{}
	if amount != nil {
		attr["amount"] = amount
	}
	return &enginev1.CheckInput{
		RequestId: "1",
		Resource:  &enginev1.Resource{Kind: kind, Id: "1", Attr: attr},
		Principal: &enginev1.Principal{Id: "sam", Roles: []string{"user"}},
		Actions:   []string{action},
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
		Resource:  &enginev1.PlanResourcesInput_Resource{Kind: kind, Attr: attr},
	}
}

func assertCELErrors(t *testing.T, entries []*enginev1.EvaluationError, wantExprs ...string) {
	t.Helper()
	var exprs []string //nolint:prealloc
	for _, entry := range entries {
		exprs = append(exprs, entry.GetCelError().GetExpression())
		require.NotEmpty(t, entry.GetCelError().GetMessage())
	}
	require.Equal(t, wantExprs, exprs)
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
