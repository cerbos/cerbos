// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"go.opencensus.io/trace"
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

func (er *EvalResult) setDefaultEffect(actions []string, effect effectv1.Effect) {
	for _, a := range actions {
		if _, ok := er.Effects[a]; !ok {
			er.Effects[a] = effect
		}
	}
}

type evalOptions struct {
	trace bool
}

type EvalOpt func(o *evalOptions)

// WithTrace enables tracing evaluation.
func WithTrace() EvalOpt {
	return func(eo *evalOptions) {
		eo.trace = true
	}
}

func getEvalOptions(options []EvalOpt) *evalOptions {
	evalOpt := &evalOptions{}
	for _, opt := range options {
		opt(evalOpt)
	}

	return evalOpt
}

type Evaluator interface {
	Evaluate(context.Context, *enginev1.CheckInput, ...EvalOpt) (*EvalResult, error)
}

func NewEvaluator(rps *runtimev1.RunnablePolicySet) Evaluator {
	switch rp := rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		return &resourcePolicyEvaluator{policy: rp.ResourcePolicy}
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		return &principalPolicyEvaluator{policy: rp.PrincipalPolicy}
	default:
		return noopEvaluator{}
	}
}

type noopEvaluator struct{}

func (noopEvaluator) Evaluate(_ context.Context, _ *enginev1.CheckInput, _ ...EvalOpt) (*EvalResult, error) {
	return nil, ErrPolicyNotExecutable
}

type resourcePolicyEvaluator struct {
	policy *runtimev1.RunnableResourcePolicySet
}

func (rpe *resourcePolicyEvaluator) Evaluate(ctx context.Context, input *enginev1.CheckInput, options ...EvalOpt) (*EvalResult, error) {
	ctx, span := tracing.StartSpan(ctx, "resource_policy.Evaluate")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("policy", rpe.policy.Meta.Fqn))

	evalOpt := getEvalOptions(options)
	tracer := NewTracer(evalOpt.trace)
	defer tracer.LogOutput(ctx)

	result := newEvalResult(namer.PolicyKeyFromModuleName(rpe.policy.Meta.Fqn), input.Actions)
	effectiveRoles := toSet(input.Principal.Roles)

	for _, p := range rpe.policy.Policies {
		tctx := tracer.Trace(cnPolicy(rpe.policy.Meta.Fqn, p.Scope))

		// evaluate the variables of this policy
		variables, err := evaluateVariables(tctx.Trace(cnVariables), p.Variables, input)
		if err != nil {
			tctx.Error(err, "Failed to evaluate variables")
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		// calculate the set of effective derived roles
		effectiveDerivedRoles := stringSet{}
		for drName, dr := range p.DerivedRoles {
			dctx := tctx.Trace(cnDerivedRole(drName))
			if !setIntersects(dr.ParentRoles, effectiveRoles) {
				dctx.Skip("Roles did not match")
				continue
			}

			// evaluate variables of this derived roles set
			drVariables, err := evaluateVariables(dctx.Trace(cnVariables), dr.Variables, input)
			if err != nil {
				dctx.SkipErr(err)
				continue
			}

			ok, err := satisfiesCondition(dctx.Trace(cnCondition), dr.Condition, drVariables, input)
			if err != nil {
				dctx.SkipErr(err)
				continue
			}

			if !ok {
				dctx.Skip("condition not satisfied")
				continue
			}

			effectiveDerivedRoles[drName] = struct{}{}
			dctx.Activate("condition satisfied")
		}

		result.EffectiveDerivedRoles = effectiveDerivedRoles

		// evaluate each rule until all actions have a result
		for _, rule := range p.Rules {
			rctx := tctx.Trace(cnRule(rule.Name))
			if !setIntersects(rule.Roles, effectiveRoles) && !setIntersects(rule.DerivedRoles, effectiveDerivedRoles) {
				rctx.Skip("no matching roles or derived roles")
				continue
			}

			for actionGlob := range rule.Actions {
				matchedActions := globMatch(actionGlob, input.Actions)
				for _, action := range matchedActions {
					ok, err := satisfiesCondition(rctx.Trace(cnAction(action)), rule.Condition, variables, input)
					if err != nil {
						rctx.SkipErr(err)
						continue
					}

					if !ok {
						rctx.Skip("condition not satisfied")
						continue
					}

					result.setEffect(action, rule.Effect)
					rctx.Activate("condition satisfied")
				}
			}
		}
	}

	// set the default effect for actions that were not matched
	result.setDefaultEffect(input.Actions, effectv1.Effect_EFFECT_DENY)

	return result, nil
}

type principalPolicyEvaluator struct {
	policy *runtimev1.RunnablePrincipalPolicySet
}

func (ppe *principalPolicyEvaluator) Evaluate(ctx context.Context, input *enginev1.CheckInput, options ...EvalOpt) (*EvalResult, error) {
	ctx, span := tracing.StartSpan(ctx, "principal_policy.Evaluate")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("policy", ppe.policy.Meta.Fqn))

	evalOpt := getEvalOptions(options)
	tracer := NewTracer(evalOpt.trace)
	result := newEvalResult(namer.PolicyKeyFromModuleName(ppe.policy.Meta.Fqn), input.Actions)

	for _, p := range ppe.policy.Policies {
		tctx := tracer.Trace(cnPolicy(ppe.policy.Meta.Fqn, p.Scope))

		// evaluate the variables of this policy
		variables, err := evaluateVariables(tctx.Trace(cnVariables), p.Variables, input)
		if err != nil {
			tctx.Error(err, "Failed to evaluate variables")
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		for resource, resourceRules := range p.ResourceRules {
			rctx := tracer.Trace(cnResource(resource))
			if !globs.matches(resource, input.Resource.Kind) {
				rctx.Skip("Did not match input resource kind")
				continue
			}

			for actionGlob, rule := range resourceRules.ActionRules {
				matchedActions := globMatch(actionGlob, input.Actions)
				for _, action := range matchedActions {
					actx := rctx.Trace(cnAction(action))
					ok, err := satisfiesCondition(actx.Trace(cnCondition), rule.Condition, variables, input)
					if err != nil {
						actx.SkipErr(err)
						continue
					}

					if !ok {
						actx.Skip("Condition not satisfied")
						continue
					}
					result.Effects[action] = rule.Effect
					actx.Activate(rule.Effect.String())
				}
			}
		}
	}

	result.setDefaultEffect(input.Actions, effectv1.Effect_EFFECT_NO_MATCH)
	return result, nil
}

func evaluateVariables(tctx TraceContext, variables map[string]*runtimev1.Expr, input *enginev1.CheckInput) (map[string]interface{}, error) {
	var errs error
	evalVars := make(map[string]interface{}, len(variables))
	for varName, varExpr := range variables {
		vctx := tctx.Trace(cnVariableExpr(varName, varExpr.Original))
		val, err := evaluateCELExpr(varExpr.Checked, evalVars, input)
		if err != nil {
			vctx.Error(err, "Failed to evaluate variable")
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s := %s`: %w", varName, varExpr.Original, err))
			continue
		}

		evalVars[varName] = val
		vctx.Info("%s := %v", varName, val)
	}

	return evalVars, errs
}

func satisfiesCondition(tctx TraceContext, cond *runtimev1.Condition, variables map[string]interface{}, input *enginev1.CheckInput) (bool, error) {
	if cond == nil {
		tctx.Info("Result = true")
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		ectx := tctx.Trace(cnCondExpr(t.Expr.Original))
		val, err := evaluateBoolCELExpr(t.Expr.Checked, variables, input)
		if err != nil {
			ectx.Error(err, "Result = false")
			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		ectx.Info("Result = %v", val)
		return val, nil
	case *runtimev1.Condition_All:
		actx := tctx.Trace(cnCondAll)
		for i, expr := range t.All.Expr {
			val, err := satisfiesCondition(actx.Trace(cnCondN(i)), expr, variables, input)
			if err != nil {
				actx.Error(err, "Result = false (short-circuited)")
				return false, err
			}

			if !val {
				actx.Info("Result = false (short-circuited)")
				return false, nil
			}
		}

		actx.Info("Result == true")
		return true, nil
	case *runtimev1.Condition_Any:
		actx := tctx.Trace(cnCondAny)
		for i, expr := range t.Any.Expr {
			val, err := satisfiesCondition(actx.Trace(cnCondN(i)), expr, variables, input)
			if err != nil {
				actx.Error(err, "Result = false (short-circuited)")
				return false, err
			}

			if val {
				actx.Info("Result = true (short-circuited)")
				return true, nil
			}
		}

		actx.Info("Result = false")
		return false, nil
	case *runtimev1.Condition_None:
		actx := tctx.Trace(cnCondNone)
		for i, expr := range t.None.Expr {
			val, err := satisfiesCondition(actx.Trace(cnCondN(i)), expr, variables, input)
			if err != nil {
				actx.Error(err, "Result = false (short-circuited)")
				return false, err
			}

			if val {
				actx.Info("Result = false (short-circuited)")
				return false, nil
			}
		}

		actx.Info("Result = true")
		return true, nil
	default:
		return false, fmt.Errorf("unknown op type %T", t)
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

func setIntersection(s1 protoSet, s2 stringSet) stringSet {
	r := stringSet{}

	for v := range s2 {
		if _, ok := s1[v]; ok {
			r[v] = struct{}{}
		}
	}

	return r
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
