// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/emptypb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

var ErrPolicyNotExecutable = errors.New("policy not executable")

type Evaluator interface {
	Evaluate(context.Context, tracer.Context, *enginev1.CheckInput) (*PolicyEvalResult, error)
	EvaluateResourcesQueryPlan(ctx context.Context, request *enginev1.PlanResourcesInput) (*PolicyPlanResult, error)
}

func NewEvaluator(rps *runtimev1.RunnablePolicySet, schemaMgr schema.Manager) Evaluator {
	switch rp := rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		return &resourcePolicyEvaluator{policy: rp.ResourcePolicy, schemaMgr: schemaMgr}
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		return &principalPolicyEvaluator{policy: rp.PrincipalPolicy}
	default:
		return noopEvaluator{}
	}
}

type noopEvaluator struct{}

func (e noopEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, request *enginev1.PlanResourcesInput) (*PolicyPlanResult, error) {
	return nil, ErrPolicyNotExecutable
}

func (noopEvaluator) Evaluate(_ context.Context, _ tracer.Context, _ *enginev1.CheckInput) (*PolicyEvalResult, error) {
	return nil, ErrPolicyNotExecutable
}

type resourcePolicyEvaluator struct {
	policy    *runtimev1.RunnableResourcePolicySet
	schemaMgr schema.Manager
}

func (rpe *resourcePolicyEvaluator) Evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	_, span := tracing.StartSpan(ctx, "resource_policy.Evaluate")
	span.SetAttributes(tracing.PolicyFQN(rpe.policy.Meta.Fqn))
	defer span.End()

	policyKey := namer.PolicyKeyFromFQN(rpe.policy.Meta.Fqn)
	result := newEvalResult(input.Actions)
	effectiveRoles := toSet(input.Principal.Roles)

	pctx := tctx.StartPolicy(rpe.policy.Meta.Fqn)

	// validate the input
	vr, err := rpe.schemaMgr.ValidateCheckInput(ctx, rpe.policy.Schemas, input)
	if err != nil {
		pctx.Failed(err, "Error during validation")

		return nil, fmt.Errorf("failed to validate input: %w", err)
	}

	if len(vr.Errors) > 0 {
		result.ValidationErrors = vr.Errors.SchemaErrors()

		pctx.Failed(vr.Errors, "Validation errors")

		if vr.Reject {
			for _, action := range input.Actions {
				actx := pctx.StartAction(action)

				result.setEffect(action, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: policyKey})

				actx.AppliedEffect(effectv1.Effect_EFFECT_DENY, "Rejected due to validation failures")
			}
			return result, nil
		}
	}

	// evaluate policies in the set
	for _, p := range rpe.policy.Policies {
		// Get the actions that are yet to be resolved. This is to implement first-match-wins semantics.
		// Within the context of a single policy, later rules can potentially override the result for an action (unless it was DENY).
		actionsToResolve := result.unresolvedActions()
		if len(actionsToResolve) == 0 {
			return result, nil
		}

		sctx := pctx.StartScope(p.Scope)

		// evaluate the variables of this policy
		variables, err := evaluateVariables(sctx.StartVariables(), p.Variables, input)
		if err != nil {
			sctx.Failed(err, "Failed to evaluate variables")
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		// calculate the set of effective derived roles
		effectiveDerivedRoles := stringSet{}
		for drName, dr := range p.DerivedRoles {
			dctx := sctx.StartDerivedRole(drName)
			if !setIntersects(dr.ParentRoles, effectiveRoles) {
				dctx.Skipped(nil, "No matching roles")
				continue
			}

			// evaluate variables of this derived roles set
			drVariables, err := evaluateVariables(dctx.StartVariables(), dr.Variables, input)
			if err != nil {
				dctx.Skipped(err, "Error evaluating variables")
				continue
			}

			ok, err := satisfiesCondition(dctx.StartCondition(), dr.Condition, drVariables, input)
			if err != nil {
				dctx.Skipped(err, "Error evaluating condition")
				continue
			}

			if !ok {
				dctx.Skipped(nil, "Condition not satisfied")
				continue
			}

			effectiveDerivedRoles[drName] = struct{}{}
			result.EffectiveDerivedRoles[drName] = struct{}{}

			dctx.Activated()
		}

		// evaluate each rule until all actions have a result
		for _, rule := range p.Rules {
			rctx := sctx.StartRule(rule.Name)
			if !setIntersects(rule.Roles, effectiveRoles) && !setIntersects(rule.DerivedRoles, effectiveDerivedRoles) {
				rctx.Skipped(nil, "No matching roles or derived roles")
				continue
			}

			for actionGlob := range rule.Actions {
				matchedActions := util.FilterGlob(actionGlob, actionsToResolve)
				for _, action := range matchedActions {
					actx := rctx.StartAction(action)
					ok, err := satisfiesCondition(actx.StartCondition(), rule.Condition, variables, input)
					if err != nil {
						actx.Skipped(err, "Error evaluating condition")
						continue
					}

					if !ok {
						actx.Skipped(nil, "Condition not satisfied")
						continue
					}

					result.setEffect(action, EffectInfo{Effect: rule.Effect, Policy: policyKey, Scope: p.Scope})
					actx.AppliedEffect(rule.Effect, "")
				}
			}
		}
	}

	// set the default effect for actions that were not matched
	result.setDefaultEffect(pctx, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: policyKey})

	return result, nil
}

type principalPolicyEvaluator struct {
	policy *runtimev1.RunnablePrincipalPolicySet
}

func (ppe *principalPolicyEvaluator) Evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	_, span := tracing.StartSpan(ctx, "principal_policy.Evaluate")
	span.SetAttributes(tracing.PolicyFQN(ppe.policy.Meta.Fqn))
	defer span.End()

	policyKey := namer.PolicyKeyFromFQN(ppe.policy.Meta.Fqn)
	result := newEvalResult(input.Actions)

	pctx := tctx.StartPolicy(ppe.policy.Meta.Fqn)
	for _, p := range ppe.policy.Policies {
		actionsToResolve := result.unresolvedActions()
		if len(actionsToResolve) == 0 {
			return result, nil
		}

		sctx := pctx.StartScope(p.Scope)
		// evaluate the variables of this policy
		variables, err := evaluateVariables(sctx.StartVariables(), p.Variables, input)
		if err != nil {
			sctx.Failed(err, "Failed to evaluate variables")
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		for resource, resourceRules := range p.ResourceRules {
			rctx := sctx.StartResource(resource)
			if !util.MatchesGlob(resource, input.Resource.Kind) {
				rctx.Skipped(nil, "Did not match input resource kind")
				continue
			}

			for _, rule := range resourceRules.ActionRules {
				matchedActions := util.FilterGlob(rule.Action, actionsToResolve)
				for _, action := range matchedActions {
					actx := rctx.StartAction(action)
					ok, err := satisfiesCondition(actx.StartCondition(), rule.Condition, variables, input)
					if err != nil {
						actx.Skipped(err, "Error evaluating condition")
						continue
					}

					if !ok {
						actx.Skipped(nil, "Condition not satisfied")
						continue
					}
					result.setEffect(action, EffectInfo{Effect: rule.Effect, Policy: policyKey, Scope: p.Scope})
					actx.AppliedEffect(rule.Effect, "")
				}
			}
		}
	}

	result.setDefaultEffect(pctx, EffectInfo{Effect: effectv1.Effect_EFFECT_NO_MATCH})
	return result, nil
}

func evaluateVariables(tctx tracer.Context, variables map[string]*runtimev1.Expr, input *enginev1.CheckInput) (map[string]any, error) {
	var errs error
	evalVars := make(map[string]any, len(variables))
	for varName, varExpr := range variables {
		vctx := tctx.StartVariable(varName, varExpr.Original)
		val, err := evaluateCELExpr(varExpr.Checked, evalVars, input)
		if err != nil {
			vctx.Skipped(err, "Failed to evaluate expression")
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s := %s`: %w", varName, varExpr.Original, err))
			continue
		}

		evalVars[varName] = val
		vctx.ComputedResult(val)
	}

	return evalVars, errs
}

func satisfiesCondition(tctx tracer.Context, cond *runtimev1.Condition, variables map[string]any, input *enginev1.CheckInput) (bool, error) {
	if cond == nil {
		tctx.ComputedBoolResult(true, nil, "")
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		ectx := tctx.StartExpr(t.Expr.Original)
		val, err := evaluateBoolCELExpr(t.Expr.Checked, variables, input)
		if err != nil {
			ectx.ComputedBoolResult(false, err, "Failed to evaluate expression")
			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		ectx.ComputedBoolResult(val, nil, "")
		return val, nil

	case *runtimev1.Condition_All:
		actx := tctx.StartConditionAll()
		for i, expr := range t.All.Expr {
			val, err := satisfiesCondition(actx.StartNthCondition(i), expr, variables, input)
			if err != nil {
				actx.ComputedBoolResult(false, err, "Short-circuited")
				return false, err
			}

			if !val {
				actx.ComputedBoolResult(false, nil, "Short-circuited")
				return false, nil
			}
		}

		actx.ComputedBoolResult(true, nil, "")
		return true, nil

	case *runtimev1.Condition_Any:
		actx := tctx.StartConditionAny()
		for i, expr := range t.Any.Expr {
			val, err := satisfiesCondition(actx.StartNthCondition(i), expr, variables, input)
			if err != nil {
				actx.ComputedBoolResult(false, err, "Short-circuited")
				return false, err
			}

			if val {
				actx.ComputedBoolResult(true, nil, "Short-circuited")
				return true, nil
			}
		}

		actx.ComputedBoolResult(false, nil, "")
		return false, nil

	case *runtimev1.Condition_None:
		actx := tctx.StartConditionNone()
		for i, expr := range t.None.Expr {
			val, err := satisfiesCondition(actx.StartNthCondition(i), expr, variables, input)
			if err != nil {
				actx.ComputedBoolResult(false, err, "Short-circuited")
				return false, err
			}

			if val {
				actx.ComputedBoolResult(false, nil, "Short-circuited")
				return false, nil
			}
		}

		actx.ComputedBoolResult(true, nil, "")
		return true, nil

	default:
		err := fmt.Errorf("unknown op type %T", t)
		tctx.ComputedBoolResult(false, err, "Unknown op type")
		return false, err
	}
}

func evaluateBoolCELExpr(expr *exprpb.CheckedExpr, variables map[string]any, input *enginev1.CheckInput) (bool, error) {
	val, err := evaluateCELExpr(expr, variables, input)
	if err != nil {
		return false, err
	}

	if val == nil {
		return false, nil
	}

	boolVal, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result: wanted bool, got %T", val)
	}

	return boolVal, nil
}

func evaluateCELExpr(expr *exprpb.CheckedExpr, variables map[string]any, input *enginev1.CheckInput) (any, error) {
	if expr == nil {
		return nil, nil
	}

	result, _, err := conditions.Eval(conditions.StdEnv, cel.CheckedExprToAst(expr), map[string]any{
		conditions.CELRequestIdent:    input,
		conditions.CELResourceAbbrev:  input.Resource,
		conditions.CELPrincipalAbbrev: input.Principal,
		conditions.CELVariablesIdent:  variables,
		conditions.CELVariablesAbbrev: variables,
	})
	if err != nil {
		// ignore expressions that access non-existent keys
		noSuchKey := &conditions.NoSuchKeyError{}
		if errors.As(err, &noSuchKey) {
			return nil, nil
		}

		return nil, err
	}

	return result.Value(), nil
}

type protoSet map[string]*emptypb.Empty

type stringSet map[string]struct{}

func toSet(values []string) stringSet {
	s := make(stringSet, len(values))
	for _, v := range values {
		s[v] = struct{}{}
	}

	return s
}

func setIntersects(s1 protoSet, s2 stringSet) bool {
	for v := range s1 {
		if v == compile.AnyRoleVal {
			return true
		}

		if _, ok := s2[v]; ok {
			return true
		}
	}

	return false
}

type EffectInfo struct {
	Policy string
	Scope  string
	Effect effectv1.Effect
}

type PolicyEvalResult struct {
	Effects               map[string]EffectInfo
	EffectiveDerivedRoles map[string]struct{}
	toResolve             map[string]struct{}
	ValidationErrors      []*schemav1.ValidationError
}

func newEvalResult(actions []string) *PolicyEvalResult {
	per := &PolicyEvalResult{
		Effects:               make(map[string]EffectInfo, len(actions)),
		EffectiveDerivedRoles: make(map[string]struct{}),
		toResolve:             make(map[string]struct{}, len(actions)),
	}

	for _, a := range actions {
		per.toResolve[a] = struct{}{}
	}

	return per
}

func (er *PolicyEvalResult) unresolvedActions() []string {
	if len(er.toResolve) == 0 {
		return nil
	}

	res := make([]string, len(er.toResolve))
	i := 0
	for ua := range er.toResolve {
		res[i] = ua
		i++
	}

	return res
}

// setEffect sets the effect for an action. DENY always takes precedence.
func (er *PolicyEvalResult) setEffect(action string, effect EffectInfo) {
	delete(er.toResolve, action)

	if effect.Effect == effectv1.Effect_EFFECT_DENY {
		er.Effects[action] = effect
		return
	}

	current, ok := er.Effects[action]
	if !ok {
		er.Effects[action] = effect
		return
	}

	if current.Effect != effectv1.Effect_EFFECT_DENY {
		er.Effects[action] = effect
	}
}

func (er *PolicyEvalResult) setDefaultEffect(tctx tracer.Context, effect EffectInfo) {
	for a := range er.toResolve {
		er.Effects[a] = effect
		tctx.StartAction(a).AppliedEffect(effect.Effect, "Default effect")
	}
}
