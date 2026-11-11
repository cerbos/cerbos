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

// planCheckResidualErrorCases lists the engine test cases in which a residual may fail to evaluate
// against the resource, with the reason. Such a residual yields neither allow nor deny, so the action is
// counted as indeterminate. Actions whose residual does evaluate must still match, and in any other
// case a residual error fails the test.
var planCheckResidualErrorCases = map[string]string{
	"case_53": "the cel_errors policies have conditions that fail on purpose",
	"case_54": "the cel_errors policies have conditions that fail on purpose",
	"case_55": "the cel_errors policies have conditions that fail on purpose",
}

type planCheckCounts struct {
	matched, indeterminate int
}

// TestPlanCheckEquivalence checks that for every input in the Check corpus, the residual AST that Plan
// builds for each action, evaluated against the input's resource, agrees with the Check effect.
// Each case runs with the lenient scope search and strict evaluation settings that it declares.
func TestPlanCheckEquivalence(t *testing.T) {
	rt := mkStoreRuleTable(t)
	schemaMgr, err := schema.NewStaticFromConf(schema.NewConf(schema.EnforcementNone), rt.Schemas, rt.JsonSchemas)
	require.NoError(t, err)

	now := time.Now()
	nowFn := func() time.Time { return now }

	var counts planCheckCounts
	for _, tcase := range test.LoadTestCases(t, "engine") {
		t.Run(tcase.Name, func(t *testing.T) {
			_, allowResidualErrors := planCheckResidualErrorCases[tcase.Name]

			tc := test.Parse[privatev1.EngineTestCase](t, tcase.Input)
			for _, lenientScopeSearch := range tc.GetConfig().GetLenientScopeSearch() {
				for _, strictEvaluation := range tc.GetConfig().GetStrictEvaluation() {
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
							comparePlanWithCheck(t, rt, schemaMgr, conf, nowFn, i, input, allowResidualErrors, &counts)
						}
					})
				}
			}
		})
	}

	t.Logf("matched=%d indeterminate=%d", counts.matched, counts.indeterminate)
}

// comparePlanWithCheck runs Check and Plan for one input and compares each action's outcome. A mismatch
// fails the test, and so does a residual that fails to evaluate unless allowResidualErrors is set.
func comparePlanWithCheck(t *testing.T, rt *RuleTable, schemaMgr schema.Manager, conf *evaluator.Conf, nowFn func() time.Time, idx int, input *enginev1.CheckInput, allowResidualErrors bool, counts *planCheckCounts) {
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
		checkEffect := outputs[0].Actions[action].GetEffect()
		wantAllow := checkEffect == effectv1.Effect_EFFECT_ALLOW

		var haveAllow bool
		var residual *planner.QpN
		var residualErr error
		if earlyOutput == nil {
			ap, err := rt.planAction(ctx, p, action)
			require.NoError(t, err)

			residual = ap.ast
			haveAllow, residualErr = evalResidual(ctx, residual, input, conf.Globals, nowFn)
		}

		describe := func() string {
			return fmt.Sprintf("input[%d] action=%s resource=%s/%s check=%s plan=%t residualErr=%v evaluationErrors=%v\nresidual: %s\ninput: %s",
				idx, action, input.Resource.Kind, input.Resource.Id, checkEffect, haveAllow, residualErr, outputs[0].EvaluationErrors, astString(residual), protojson.Format(input))
		}

		switch {
		case residualErr != nil && allowResidualErrors:
			counts.indeterminate++
		case residualErr != nil:
			t.Errorf("residual failed to evaluate: %s", describe())
		case haveAllow != wantAllow:
			t.Errorf("mismatch: %s", describe())
		default:
			counts.matched++
		}
	}
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
