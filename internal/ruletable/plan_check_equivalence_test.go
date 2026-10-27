// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable/planner"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

// planCheckSkip lists engine test cases excluded from the equivalence check, with the reason.
var planCheckSkip = map[string]string{}

// TestPlanCheckEquivalence checks that for every input in the Check corpus, the residual AST that Plan
// builds for each action, evaluated against the input's resource, agrees with the Check effect.
// See plan_check_equivalence.md.
func TestPlanCheckEquivalence(t *testing.T) {
	rt := mkStoreRuleTable(t)
	schemaMgr, err := schema.NewStaticFromConf(schema.NewConf(schema.EnforcementNone), rt.Schemas, rt.JsonSchemas)
	require.NoError(t, err)

	now := time.Now()
	nowFn := func() time.Time { return now }

	var matched, indeterminate int
	for _, tcase := range test.LoadTestCases(t, "engine") {
		t.Run(tcase.Name, func(t *testing.T) {
			if reason, ok := planCheckSkip[tcase.Name]; ok {
				t.Skip(reason)
			}

			tc := test.Parse[privatev1.EngineTestCase](t, tcase.Input)
			for _, lenientScopeSearch := range []bool{false, true} {
				for _, strictEvaluation := range []bool{false, true} {
					conf := &evaluator.Conf{}
					conf.SetDefaults()
					if v := tc.GetConfig().GetDefaultPolicyVersion(); v != "" {
						conf.DefaultPolicyVersion = v
					}
					conf.DefaultScope = tc.GetConfig().GetDefaultScope()
					conf.Globals = (&structpb.Struct{Fields: tc.GetConfig().GetGlobals()}).AsMap()
					conf.LenientScopeSearch = lenientScopeSearch
					conf.StrictEvaluation = strictEvaluation

					t.Run(fmt.Sprintf("lenient_scope_search=%t/strict_evaluation=%t", lenientScopeSearch, strictEvaluation), func(t *testing.T) {
						for i, input := range tc.Inputs {
							m, ind := comparePlanWithCheck(t, rt, schemaMgr, conf, nowFn, i, input)
							matched += m
							indeterminate += ind
						}
					})
				}
			}
		})
	}

	t.Logf("matched=%d indeterminate=%d", matched, indeterminate)
}

// comparePlanWithCheck runs Check and Plan for one input and compares each action's outcome.
// It returns the number of matching and indeterminate actions; mismatches fail the test.
func comparePlanWithCheck(t *testing.T, rt *RuleTable, schemaMgr schema.Manager, conf *evaluator.Conf, nowFn func() time.Time, idx int, input *enginev1.CheckInput) (matched, indeterminate int) {
	t.Helper()

	ctx := t.Context()
	opts := []evaluator.CheckOpt{evaluator.WithNowFunc(nowFn)}

	outputs, _, err := rt.Check(ctx, conf, schemaMgr, []*enginev1.CheckInput{input}, opts...)
	require.NoError(t, err)
	require.Len(t, outputs, 1)

	planInput := &enginev1.PlanResourcesInput{
		RequestId: input.RequestId,
		Principal: input.Principal,
		Resource: &enginev1.PlanResourcesInput_Resource{
			Kind:          input.Resource.Kind,
			PolicyVersion: input.Resource.PolicyVersion,
			Scope:         input.Resource.Scope,
		},
		Actions: input.Actions,
		AuxData: input.AuxData,
	}

	evalParams := evaluator.NewCheckOptions(ctx, conf, opts...).EvalParams
	p, earlyOutput, err := rt.newPlanRequest(ctx, trace.SpanFromContext(ctx), schemaMgr, planInput, evalParams)
	require.NoError(t, err)

	for _, action := range input.Actions {
		wantAllow := outputs[0].Actions[action].GetEffect() == effectv1.Effect_EFFECT_ALLOW

		var haveAllow bool
		var residual *planner.QpN
		if earlyOutput == nil {
			ap, err := rt.planAction(ctx, p, action)
			require.NoError(t, err)

			residual = ap.ast
			haveAllow, err = evalResidual(ctx, residual, input, conf.Globals, nowFn)
			if err != nil {
				t.Logf("indeterminate: input[%d] resource=%s/%s action=%s check=%s: %v\nresidual: %s",
					idx, input.Resource.Kind, input.Resource.Id, action, outputs[0].Actions[action].GetEffect(), err, astString(residual))
				indeterminate++
				continue
			}
		}

		if haveAllow != wantAllow && conf.StrictEvaluation && !wantAllow && len(outputs[0].EvaluationErrors) > 0 {
			// Check denied because a condition failed on the concrete resource, typically a missing
			// attribute. Plan treats the attribute as unknown, so it can't see the error.
			t.Logf("indeterminate: input[%d] resource=%s/%s action=%s: strict evaluation error in Check: %v\nresidual: %s",
				idx, input.Resource.Kind, input.Resource.Id, action, outputs[0].EvaluationErrors, astString(residual))
			indeterminate++
			continue
		}

		if haveAllow != wantAllow {
			t.Errorf("mismatch: input[%d] resource=%s/%s action=%s check=%s plan=%t\nresidual: %s\ninput: %s",
				idx, input.Resource.Kind, input.Resource.Id, action, outputs[0].Actions[action].GetEffect(), haveAllow, astString(residual), protojson.Format(input))
			continue
		}
		matched++
	}

	return matched, indeterminate
}

func astString(node *planner.QpN) string {
	if node == nil {
		return "<none: plan decided before evaluating actions>"
	}

	f, err := planner.ToFilter(node)
	if err != nil {
		return fmt.Sprintf("<%v>", err)
	}

	return planner.FilterToString(f)
}

func mkStoreRuleTable(t *testing.T) *RuleTable {
	t.Helper()
	ctx := t.Context()

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: test.PathToDir(t, "store")})
	require.NoError(t, err)

	protoRT := NewProtoRuletable()
	require.NoError(t, LoadPolicies(ctx, protoRT, compile.NewManager(store)))
	require.NoError(t, LoadSchemas(ctx, protoRT, store))

	rt, err := NewRuleTable(protoRT)
	require.NoError(t, err)

	return rt
}
