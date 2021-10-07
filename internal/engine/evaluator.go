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
	"go.uber.org/zap"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/emptypb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
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

type evalOptions struct{}

type EvalOpt func(o *evalOptions)

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
	logger := logging.FromContext(ctx).Named("evaluator").With(zap.String("policy", rpe.policy.Meta.Fqn))
	result := newEvalResult(namer.PolicyKeyFromModuleName(rpe.policy.Meta.Fqn), input.Actions)
	effectiveRoles := toSet(input.Principal.Roles)

	for _, p := range rpe.policy.Policies {
		log := logger.With(zap.Strings("scope", p.Scope))

		// evaluate the variables of this policy
		variables, err := evaluateVariables(log, p.Variables, input)
		if err != nil {
			log.Error("Failed to evaluate variables", zap.Error(err))
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		// calculate the set of effective derived roles
		effectiveDerivedRoles := stringSet{}
		for drName, dr := range p.DerivedRoles {
			if !setIntersects(dr.ParentRoles, effectiveRoles) {
				log.Debug("Derived role not activated", zap.String("derived_role", drName), zap.String("cause", "no matching roles"))
				continue
			}

			// evaluate variables of this derived roles set
			drVariables, err := evaluateVariables(log, dr.Variables, input)
			if err != nil {
				log.Debug("Derived role not activated",
					zap.String("derived_role", drName),
					zap.String("cause", "error evaluating derived role variables"),
					zap.Error(err))
				// TODO(cell) Identify "undefined vars" errors and skip only those instead of everything.
				continue
			}

			ok, err := satisfiesCondition(log, dr.Condition, drVariables, input)
			if err != nil {
				log.Debug("Derived role not activated",
					zap.String("derived_role", drName),
					zap.String("cause", "error evaluating condition"),
					zap.Error(err))
				// TODO(cell) Identify "undefined vars" errors and skip only those instead of everything.
				continue
			}

			if !ok {
				log.Debug("Derived role not activated",
					zap.String("derived_role", drName),
					zap.String("cause", "condition not satisfied"))
				continue
			}

			effectiveDerivedRoles[drName] = struct{}{}
			log.Debug("Derived role activated", zap.String("derived_role", drName))
		}

		result.EffectiveDerivedRoles = effectiveDerivedRoles

		// evaluate each rule until all actions have a result
		for _, rule := range p.Rules {
			if !setIntersects(rule.Roles, effectiveRoles) && !setIntersects(rule.DerivedRoles, effectiveDerivedRoles) {
				log.Debug("Rule not activated",
					zap.String("rule", rule.Name),
					zap.String("cause", "no matching roles"))
				continue
			}

			for actionGlob := range rule.Actions {
				matchedActions := globMatch(actionGlob, input.Actions)
				for _, action := range matchedActions {
					ok, err := satisfiesCondition(log, rule.Condition, variables, input)
					if err != nil {
						log.Debug("Rule not activated",
							zap.String("rule", rule.Name),
							zap.String("action", action),
							zap.String("cause", "error evaluating condition"),
							zap.Error(err))
						continue
					}

					if !ok {
						log.Debug("Rule not activated",
							zap.String("rule", rule.Name),
							zap.String("action", action),
							zap.String("cause", "condition not satisfied"))
						continue
					}

					result.setEffect(action, rule.Effect)
					log.Debug("Rule activated",
						zap.String("rule", rule.Name),
						zap.String("action", action),
						zap.Stringer("effect", rule.Effect))
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
	logger := logging.FromContext(ctx).Named("evaluator").With(zap.String("policy", ppe.policy.Meta.Fqn))
	result := newEvalResult(namer.PolicyKeyFromModuleName(ppe.policy.Meta.Fqn), input.Actions)

	for _, p := range ppe.policy.Policies {
		log := logger.With(zap.Strings("scope", p.Scope))

		// evaluate the variables of this policy
		variables, err := evaluateVariables(log, p.Variables, input)
		if err != nil {
			log.Error("Failed to evaluate variables", zap.Error(err))
			return nil, fmt.Errorf("failed to evaluate variables: %w", err)
		}

		for resource, resourceRules := range p.ResourceRules {
			if !globs.matches(resource, input.Resource.Kind) {
				continue
			}

			for actionGlob, rule := range resourceRules.ActionRules {
				matchedActions := globMatch(actionGlob, input.Actions)
				for _, action := range matchedActions {
					ok, err := satisfiesCondition(log, rule.Condition, variables, input)
					if err != nil {
						log.Debug("Rule not activated",
							zap.String("resource", resource),
							zap.String("rule", rule.Name),
							zap.String("action", action),
							zap.String("cause", "error evaluating condition"),
							zap.Error(err))
						continue
					}

					if !ok {
						log.Debug("Rule not activated",
							zap.String("resource", resource),
							zap.String("rule", rule.Name),
							zap.String("action", action),
							zap.String("cause", "condition not satisfied"))
						continue
					}
					result.Effects[action] = rule.Effect
					log.Debug("Rule activated",
						zap.String("resource", resource),
						zap.String("rule", rule.Name),
						zap.String("action", action),
						zap.Stringer("effect", rule.Effect))
				}
			}
		}
	}

	result.setDefaultEffect(input.Actions, effectv1.Effect_EFFECT_NO_MATCH)
	return result, nil
}

func evaluateVariables(log *zap.Logger, variables map[string]*runtimev1.Expr, input *enginev1.CheckInput) (map[string]interface{}, error) {
	var errs error
	evalVars := make(map[string]interface{}, len(variables))
	for varName, varExpr := range variables {
		val, err := evaluateCELExpr(varExpr.Checked, evalVars, input)
		if err != nil {
			log.Debug("Variable evaluation failed",
				zap.String("variable", varName),
				zap.String("expression", varExpr.Original),
				zap.Error(err))
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s := %s`: %w", varName, varExpr.Original, err))
			continue
		}

		evalVars[varName] = val
		log.Debug("Variable evaluated",
			zap.String("variable", varName),
			zap.String("expression", varExpr.Original),
			zap.Any("value", val))
	}

	return evalVars, errs
}

func satisfiesCondition(log *zap.Logger, cond *runtimev1.Condition, variables map[string]interface{}, input *enginev1.CheckInput) (bool, error) {
	if cond == nil {
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		val, err := evaluateBoolCELExpr(t.Expr.Checked, variables, input)
		if err != nil {
			log.Debug("Failed to evaluate condition expression",
				zap.String("expression", t.Expr.Original),
				zap.Error(err))

			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		log.Debug("Evaluated condition expression",
			zap.String("expression", t.Expr.Original),
			zap.Bool("value", val))

		return val, nil
	case *runtimev1.Condition_All:
		log.Debug("Evaluating ALL")
		for _, expr := range t.All.Expr {
			val, err := satisfiesCondition(log, expr, variables, input)
			if err != nil {
				log.Debug("Short-circuiting ALL due to error", zap.Error(err))
				return false, err
			}

			if !val {
				log.Debug("Short-circuiting ALL due to false value")
				return false, nil
			}
		}

		return true, nil
	case *runtimev1.Condition_Any:
		log.Debug("Evaluating ANY")
		for _, expr := range t.Any.Expr {
			val, err := satisfiesCondition(log, expr, variables, input)
			if err != nil {
				log.Debug("Short-circuiting ANY due to error", zap.Error(err))
				return false, err
			}

			if val {
				log.Debug("Short-circuiting ANY due to false value")
				return true, nil
			}
		}

		return false, nil
	case *runtimev1.Condition_None:
		log.Debug("Evaluating NONE")
		for _, expr := range t.None.Expr {
			val, err := satisfiesCondition(log, expr, variables, input)
			if err != nil {
				log.Debug("Short-circuiting NONE due to error", zap.Error(err))
				return false, err
			}

			if val {
				log.Debug("Short-circuiting NONE due to false value")
				return false, nil
			}
		}

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
