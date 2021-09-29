// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/emptypb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/observability/logging"
)

var (
	ErrPolicyNotExecutable = errors.New("policy not executable")
	ErrUnexpectedResult    = errors.New("unexpected result")
)

type EvalResult struct {
	PolicyKey             string
	Effects               map[string]effectv1.Effect
	EffectiveDerivedRoles []string
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

	result := EvalResult{
		PolicyKey: strings.TrimPrefix(rpe.policy.Meta.Fqn, "cerbos."),
		Effects:   make(map[string]effectv1.Effect, len(input.Actions)),
	}

	actionsToCheck := toSet(input.Actions)
	effectiveRoles := toSet(input.Principal.Roles)

	for _, p := range rpe.policy.Policies {
		log := logger.With(zap.Strings("scope", p.Scope))

		// calculate the set of effective derived roles
		effectiveDerivedRoles := stringSet{}
		for drName, dr := range p.DerivedRoles {
			if !setIntersects(dr.ParentRoles, effectiveRoles) {
				continue
			}

			ok, err := satisfiesCondition(dr.Condition, input)
			if err != nil {
				log.Error("Failed to evaluate condition of derived role", zap.String("derived_role", drName), zap.Error(err))
				return nil, fmt.Errorf("failed to check condition of derived role '%s': %w", drName, err)
			}

			if ok {
				effectiveDerivedRoles[drName] = struct{}{}
				result.EffectiveDerivedRoles = append(result.EffectiveDerivedRoles, drName)
			}
		}

		// evaluate each rule until all actions have a result
		for _, rule := range p.Rules {
			matchingActions := globSetIntersection(rule.Actions, actionsToCheck)
			for action := range matchingActions {
				if !setIntersects(rule.Roles, effectiveRoles) && !setIntersects(rule.DerivedRoles, effectiveDerivedRoles) {
					continue
				}

				ok, err := satisfiesCondition(rule.Condition, input)
				if err != nil {
					log.Error("Failed to evaluate condition of rule", zap.String("rule", rule.Name), zap.Error(err))
					return nil, fmt.Errorf("failed to check condition of rule '%s': %w", rule.Name, err)
				}

				if ok {
					log.Debug("Resolved effect for action", zap.String("rule", rule.Name), zap.String("action", action), zap.Stringer("effect", rule.Effect))
					result.Effects[action] = rule.Effect
					delete(actionsToCheck, action)
				}
			}

			if len(actionsToCheck) == 0 {
				return &result, nil
			}
		}
	}

	for action := range actionsToCheck {
		logger.Debug("Setting default deny effect for action", zap.String("action", action))
		result.Effects[action] = effectv1.Effect_EFFECT_DENY
	}

	return &result, nil
}

type principalPolicyEvaluator struct {
	policy *runtimev1.RunnablePrincipalPolicySet
}

func (ppe *principalPolicyEvaluator) Evaluate(ctx context.Context, input *enginev1.CheckInput, options ...EvalOpt) (*EvalResult, error) {
	logger := logging.FromContext(ctx).Named("evaluator").With(zap.String("policy", ppe.policy.Meta.Fqn))

	result := EvalResult{
		PolicyKey: strings.TrimPrefix(ppe.policy.Meta.Fqn, "cerbos."),
		Effects:   make(map[string]effectv1.Effect, len(input.Actions)),
	}

	actionsToCheck := toSet(input.Actions)

	for _, p := range ppe.policy.Policies {
		rules, ok := p.ResourceRules[input.Resource.Kind]
		if !ok {
			for resource, resourceRules := range p.ResourceRules {
				if globs.matches(resource, input.Resource.Kind) {
					rules = resourceRules
					break
				}
			}

			if rules == nil {
				continue
			}
		}

		log := logger.With(zap.Strings("scope", p.Scope))

		for actionGlob, rule := range rules.ActionRules {
			var action string
			for a := range actionsToCheck {
				if globs.matches(actionGlob, a) {
					action = a
					break
				}
			}

			if action == "" {
				continue
			}

			ok, err := satisfiesCondition(rule.Condition, input)
			if err != nil {
				log.Error("Failed to evaluate condition of rule", zap.String("rule", rule.Name), zap.Error(err))
				return nil, fmt.Errorf("failed to check condition of rule '%s': %w", rule.Name, err)
			}

			if ok {
				log.Debug("Resolved effect for action", zap.String("rule", rule.Name), zap.String("action", action), zap.Stringer("effect", rule.Effect))
				result.Effects[action] = rule.Effect
				delete(actionsToCheck, action)
			}

			if len(actionsToCheck) == 0 {
				return &result, nil
			}
		}
	}

	for action := range actionsToCheck {
		logger.Debug("Setting default no_match effect for action", zap.String("action", action))
		result.Effects[action] = effectv1.Effect_EFFECT_NO_MATCH
	}

	return &result, nil
}

func satisfiesCondition(cond *exprpb.CheckedExpr, input *enginev1.CheckInput) (bool, error) {
	if cond == nil {
		return true, nil
	}

	prg, err := codegen.CELConditionFromCheckedExpr(cond).Program()
	if err != nil {
		return false, fmt.Errorf("failed to convert checked expression to CEL program: %w", err)
	}

	result, _, err := prg.Eval(map[string]interface{}{
		codegen.CELRequestIdent:    input,
		codegen.CELResourceAbbrev:  input.Resource,
		codegen.CELPrincipalAbbrev: input.Principal,
	})
	if err != nil {
		return false, fmt.Errorf("CEL evaluation failed: %w", err)
	}

	if result == nil || result.Value() == nil {
		return false, ErrUnexpectedResult
	}

	v, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result from condition evaluation: %v", result.Value())
	}

	return v, nil
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

func globSetIntersection(s1 protoSet, s2 stringSet) stringSet {
	r := stringSet{}

	for v1 := range s1 {
		for v2 := range s2 {
			if globs.matches(v1, v2) {
				r[v2] = struct{}{}
			}
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

func globSetIntersects(s1 protoSet, s2 stringSet) bool {
	for v1 := range s1 {
		for v2 := range s2 {
			if globs.matches(v1, v2) {
				return true
			}
		}
	}

	return false
}
