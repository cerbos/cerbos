// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/emptypb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/tracing"
)

var (
	ErrPolicyNotExecutable = errors.New("policy not executable")
	ErrUnexpectedResult    = errors.New("unexpected result")
)

type Evaluator interface {
	Evaluate(context.Context, *enginev1.CheckInput) (*EvalResult, error)
}

func NewEvaluator(rps *runtimev1.RunnablePolicySet, t *tracer) Evaluator {
	switch rp := rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		return &resourcePolicyEvaluator{policy: rp.ResourcePolicy, tracer: t}
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		return &principalPolicyEvaluator{policy: rp.PrincipalPolicy, tracer: t}
	default:
		return noopEvaluator{}
	}
}

type noopEvaluator struct{}

func (noopEvaluator) Evaluate(_ context.Context, _ *enginev1.CheckInput) (*EvalResult, error) {
	return nil, ErrPolicyNotExecutable
}

type resourcePolicyEvaluator struct {
	policy *runtimev1.RunnableResourcePolicySet
	*tracer
}

func (rpe *resourcePolicyEvaluator) Evaluate(ctx context.Context, input *enginev1.CheckInput) (*EvalResult, error) {
	_, span := tracing.StartSpan(ctx, "resource_policy.Evaluate")
	span.SetAttributes(tracing.PolicyFQN(rpe.policy.Meta.Fqn))
	defer span.End()

	result := newEvalResult(namer.PolicyKeyFromFQN(rpe.policy.Meta.Fqn), input.Actions)
	effectiveRoles := toSet(input.Principal.Roles)

	tctx := rpe.beginTrace(policyComponent, rpe.policy.Meta.Fqn)
	for _, p := range rpe.policy.Policies {
		// evaluate the variables of this policy
		variables, err := evaluateVariables(tctx.beginTrace(variablesComponent), p.Variables, input)
		if err != nil {
			tctx.writeEvent(KVMsg("Failed to evaluate variables"), KVError(err))
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		// calculate the set of effective derived roles
		effectiveDerivedRoles := stringSet{}
		for drName, dr := range p.DerivedRoles {
			dctx := tctx.beginTrace(derivedRoleComponent, drName)
			if !setIntersects(dr.ParentRoles, effectiveRoles) {
				dctx.writeEvent(KVSkip(), KVMsg("No matching roles"))
				continue
			}

			// evaluate variables of this derived roles set
			drVariables, err := evaluateVariables(dctx.beginTrace(variablesComponent), dr.Variables, input)
			if err != nil {
				dctx.writeEvent(KVSkip(), KVMsg("Error evaluating variables"), KVError(err))
				continue
			}

			ok, err := satisfiesCondition(dctx.beginTrace(conditionComponent), dr.Condition, drVariables, input)
			if err != nil {
				dctx.writeEvent(KVSkip(), KVMsg("Error evaluating condition"), KVError(err))
				continue
			}

			if !ok {
				dctx.writeEvent(KVSkip(), KVMsg("Condition not satisfied"))
				continue
			}

			effectiveDerivedRoles[drName] = struct{}{}
			dctx.writeEvent(KVActivated())
		}

		result.EffectiveDerivedRoles = effectiveDerivedRoles

		// evaluate each rule until all actions have a result
		for _, rule := range p.Rules {
			rctx := tctx.beginTrace(ruleComponent, rule.Name)
			if !setIntersects(rule.Roles, effectiveRoles) && !setIntersects(rule.DerivedRoles, effectiveDerivedRoles) {
				rctx.writeEvent(KVSkip(), KVMsg("No matching roles or derived roles"))
				continue
			}

			for actionGlob := range rule.Actions {
				matchedActions := globMatch(actionGlob, input.Actions)
				for _, action := range matchedActions {
					actx := rctx.beginTrace(actionComponent, action)
					ok, err := satisfiesCondition(actx.beginTrace(conditionComponent), rule.Condition, variables, input)
					if err != nil {
						actx.writeEvent(KVSkip(), KVMsg("Error evaluating condition"), KVError(err))
						continue
					}

					if !ok {
						actx.writeEvent(KVSkip(), KVMsg("condition not satisfied"))
						continue
					}

					result.setEffect(action, rule.Effect)
					actx.writeEvent(KVActivated(), KVEffect(rule.Effect))
				}
			}
		}
	}

	// set the default effect for actions that were not matched
	result.setDefaultEffect(tctx, input.Actions, effectv1.Effect_EFFECT_DENY)

	return result, nil
}

type principalPolicyEvaluator struct {
	policy *runtimev1.RunnablePrincipalPolicySet
	*tracer
}

func (ppe *principalPolicyEvaluator) Evaluate(ctx context.Context, input *enginev1.CheckInput) (*EvalResult, error) {
	_, span := tracing.StartSpan(ctx, "principal_policy.Evaluate")
	span.SetAttributes(tracing.PolicyFQN(ppe.policy.Meta.Fqn))
	defer span.End()

	result := newEvalResult(namer.PolicyKeyFromFQN(ppe.policy.Meta.Fqn), input.Actions)

	tctx := ppe.beginTrace(policyComponent, ppe.policy.Meta.Fqn)
	for _, p := range ppe.policy.Policies {
		// evaluate the variables of this policy
		variables, err := evaluateVariables(tctx.beginTrace(variablesComponent), p.Variables, input)
		if err != nil {
			tctx.writeEvent(KVMsg("Failed to evaluate variables"), KVError(err))
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		for resource, resourceRules := range p.ResourceRules {
			rctx := tctx.beginTrace(resourceComponent, resource)
			if !globs.matches(resource, input.Resource.Kind) {
				rctx.writeEvent(KVSkip(), KVMsg("Did not match input resource kind"))
				continue
			}

			for actionGlob, rule := range resourceRules.ActionRules {
				matchedActions := globMatch(actionGlob, input.Actions)
				for _, action := range matchedActions {
					actx := rctx.beginTrace(actionComponent, action)
					ok, err := satisfiesCondition(actx.beginTrace(conditionComponent), rule.Condition, variables, input)
					if err != nil {
						actx.writeEvent(KVSkip(), KVMsg("Error evaluating condition"), KVError(err))
						continue
					}

					if !ok {
						actx.writeEvent(KVSkip(), KVMsg("condition not satisfied"))
						continue
					}
					result.Effects[action] = rule.Effect
					actx.writeEvent(KVActivated(), KVEffect(rule.Effect))
				}
			}
		}
	}

	result.setDefaultEffect(tctx, input.Actions, effectv1.Effect_EFFECT_NO_MATCH)
	return result, nil
}

func evaluateVariables(tctx *traceContext, variables map[string]*runtimev1.Expr, input *enginev1.CheckInput) (map[string]interface{}, error) {
	var errs error
	evalVars := make(map[string]interface{}, len(variables))
	for varName, varExpr := range variables {
		vctx := tctx.beginTrace(varComponent, varName, varExpr.Original)
		val, err := evaluateCELExpr(varExpr.Checked, evalVars, input)
		if err != nil {
			vctx.writeEvent(KVSkip(), KVError(err), KVMsg("Failed to evaluate variable"))
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s := %s`: %w", varName, varExpr.Original, err))
			continue
		}

		evalVars[varName] = val
		vctx.writeEvent(KVActivated(), KVMsg("%s := %v", varName, val))
	}

	return evalVars, errs
}

func satisfiesCondition(tctx *traceContext, cond *runtimev1.Condition, variables map[string]interface{}, input *enginev1.CheckInput) (bool, error) {
	if cond == nil {
		tctx.writeEvent(KVActivated(), KVResult(true))
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		ectx := tctx.beginTrace(exprComponent, t.Expr.Original)
		val, err := evaluateBoolCELExpr(t.Expr.Checked, variables, input)
		if err != nil {
			ectx.writeEvent(KVError(err), KVResult(false))
			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		ectx.writeEvent(KVResult(val))
		return val, nil
	case *runtimev1.Condition_All:
		actx := tctx.beginTrace(condAllComponent)
		for i, expr := range t.All.Expr {
			val, err := satisfiesCondition(actx.beginTrace(nthCondComponent, i), expr, variables, input)
			if err != nil {
				actx.writeEvent(KVError(err), KVResult(false), KVMsg("Short-circuited"))
				return false, err
			}

			if !val {
				actx.writeEvent(KVResult(false), KVMsg("Short-circuited"))
				return false, nil
			}
		}

		actx.writeEvent(KVResult(true))
		return true, nil
	case *runtimev1.Condition_Any:
		actx := tctx.beginTrace(condAnyComponent)
		for i, expr := range t.Any.Expr {
			val, err := satisfiesCondition(actx.beginTrace(nthCondComponent, i), expr, variables, input)
			if err != nil {
				actx.writeEvent(KVError(err), KVResult(false), KVMsg("Short-circuited"))
				return false, err
			}

			if val {
				actx.writeEvent(KVResult(true), KVMsg("Short-circuited"))
				return true, nil
			}
		}

		actx.writeEvent(KVResult(false))
		return false, nil
	case *runtimev1.Condition_None:
		actx := tctx.beginTrace(condNoneComponent)
		for i, expr := range t.None.Expr {
			val, err := satisfiesCondition(actx.beginTrace(nthCondComponent, i), expr, variables, input)
			if err != nil {
				actx.writeEvent(KVError(err), KVResult(false), KVMsg("Short-circuited"))
				return false, err
			}

			if val {
				actx.writeEvent(KVResult(false), KVMsg("Short-circuited"))
				return false, nil
			}
		}

		actx.writeEvent(KVResult(true))
		return true, nil
	default:
		err := fmt.Errorf("unknown op type %T", t)
		tctx.writeEvent(KVError(err), KVResult(false), KVMsg("Unknown op type"))
		return false, err
	}
}

func evaluateBoolCELExpr(expr *exprpb.CheckedExpr, variables map[string]interface{}, input *enginev1.CheckInput) (bool, error) {
	val, err := evaluateCELExpr(expr, variables, input)
	if err != nil {
		return false, err
	}

	boolVal, ok := val.(bool)
	if !ok {
		return false, ErrUnexpectedResult
	}

	return boolVal, nil
}

func evaluateCELExpr(expr *exprpb.CheckedExpr, variables map[string]interface{}, input *enginev1.CheckInput) (interface{}, error) {
	if expr == nil {
		return nil, nil
	}

	prg, err := conditions.StdEnv.Program(cel.CheckedExprToAst(expr))
	if err != nil {
		return nil, err
	}

	result, _, err := prg.Eval(map[string]interface{}{
		conditions.CELRequestIdent:    input,
		conditions.CELResourceAbbrev:  input.Resource,
		conditions.CELPrincipalAbbrev: input.Principal,
		conditions.CELVariablesIdent:  variables,
		conditions.CELVariablesAbbrev: variables,
	})
	if err != nil {
		// ignore expressions that access non-existent keys
		if strings.Contains(err.Error(), "no such key") {
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
	for v := range s2 {
		if _, ok := s1[v]; ok {
			return true
		}
	}

	return false
}

func globMatch(g string, values []string) []string {
	globExp := g
	// for backward compatibility, consider single * as **
	if globExp == "*" {
		globExp = "**"
	}

	var out []string

	for _, v := range values {
		if globs.matches(globExp, v) {
			out = append(out, v)
		}
	}

	return out
}

type EvalResult struct {
	PolicyKey             string
	Effects               map[string]effectv1.Effect
	EffectiveDerivedRoles map[string]struct{}
}

func newEvalResult(policyKey string, actions []string) *EvalResult {
	return &EvalResult{
		PolicyKey: policyKey,
		Effects:   make(map[string]effectv1.Effect, len(actions)),
	}
}

// setEffect sets the effect for an action. DENY always takes precedence.
func (er *EvalResult) setEffect(action string, effect effectv1.Effect) {
	if effect == effectv1.Effect_EFFECT_DENY {
		er.Effects[action] = effect
		return
	}

	current, ok := er.Effects[action]
	if !ok {
		er.Effects[action] = effect
		return
	}

	if current != effectv1.Effect_EFFECT_DENY {
		er.Effects[action] = effect
	}
}

func (er *EvalResult) setDefaultEffect(tctx *traceContext, actions []string, effect effectv1.Effect) {
	for _, a := range actions {
		if _, ok := er.Effects[a]; !ok {
			er.Effects[a] = effect
			tctx.beginTrace(actionComponent, a).writeEvent(KVEffect(effect), KVMsg("Default effect"))
		}
	}
}
