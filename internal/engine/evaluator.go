// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/multierr"
	"golang.org/x/exp/maps"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/internal"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

const noMatchScopePermissions = "NO_MATCH_FOR_SCOPE_PERMISSIONS"

var ErrPolicyNotExecutable = errors.New("policy not executable")

type evalParams struct {
	globals              map[string]any
	nowFunc              conditions.NowFunc
	defaultPolicyVersion string
	lenientScopeSearch   bool
}

func defaultEvalParams(conf *Conf) evalParams {
	return evalParams{
		globals:              conf.Globals,
		defaultPolicyVersion: conf.DefaultPolicyVersion,
		lenientScopeSearch:   conf.LenientScopeSearch,
	}
}

type evalContext struct {
	request               *enginev1.Request
	runtime               *enginev1.Runtime
	effectiveDerivedRoles internal.StringSet
	evalParams
}

func newEvalContext(ep evalParams, request *enginev1.Request) *evalContext {
	return &evalContext{
		evalParams: ep,
		request:    request,
	}
}

func (ec *evalContext) withEffectiveDerivedRoles(effectiveDerivedRoles internal.StringSet) *evalContext {
	return &evalContext{
		evalParams:            ec.evalParams,
		request:               ec.request,
		effectiveDerivedRoles: effectiveDerivedRoles,
	}
}

func (ec *evalContext) lazyRuntime() any { // We have to return `any` rather than `*enginev1.Runtime` here to be able to use this function as a lazy binding in the CEL evaluator.
	if ec.runtime == nil {
		ec.runtime = &enginev1.Runtime{}
		if len(ec.effectiveDerivedRoles) > 0 {
			ec.runtime.EffectiveDerivedRoles = ec.effectiveDerivedRoles.Values()
			sort.Strings(ec.runtime.EffectiveDerivedRoles)
		}
	}

	return ec.runtime
}

type Evaluator interface {
	Evaluate(context.Context, tracer.Context, *enginev1.CheckInput) (*PolicyEvalResult, error)
}

func NewEvaluator(rps []*runtimev1.RunnablePolicySet, schemaMgr schema.Manager, eparams evalParams) Evaluator {
	if len(rps) == 0 {
		return noopEvaluator{}
	}

	switch rp := rps[0].PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		return &resourcePolicyEvaluator{policy: rp.ResourcePolicy, schemaMgr: schemaMgr, evalParams: eparams}
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		return &principalPolicyEvaluator{policy: rp.PrincipalPolicy, evalParams: eparams}
	case *runtimev1.RunnablePolicySet_RolePolicy:
		return newRolePolicyEvaluator(rps)
	default:
		return noopEvaluator{}
	}
}

type noopEvaluator struct{}

func (noopEvaluator) Evaluate(_ context.Context, _ tracer.Context, _ *enginev1.CheckInput) (*PolicyEvalResult, error) {
	return nil, ErrPolicyNotExecutable
}

type rolePolicyEvaluator struct {
	policies map[string]*runtimev1.RunnableRolePolicySet
}

func newRolePolicyEvaluator(rps []*runtimev1.RunnablePolicySet) *rolePolicyEvaluator {
	policies := make(map[string]*runtimev1.RunnableRolePolicySet)
	for _, p := range rps {
		if rp, ok := p.PolicySet.(*runtimev1.RunnablePolicySet_RolePolicy); ok {
			policies[rp.RolePolicy.Role] = rp.RolePolicy
		}
	}

	return &rolePolicyEvaluator{policies: policies}
}

func (rpe *rolePolicyEvaluator) Evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	return tracing.RecordSpan2(ctx, "role_policy.Evaluate", func(_ context.Context, span trace.Span) (*PolicyEvalResult, error) {
		span.SetAttributes(tracing.PolicyScope(input.Principal.Scope))

		sourceAttrs := make(map[string]*policyv1.SourceAttributes)
		mergedActions := make(internal.ProtoSet)
		activeRoles := make(internal.StringSet)
		assumedRoles := []string{}
		var scopePermission policyv1.ScopePermissions // all role policies must share the same ScopePermissions
		for r, p := range rpe.policies {
			if scopePermission == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
				scopePermission = p.ScopePermissions
			}

			if p.GetMeta().GetFqn() != "" && p.GetMeta().GetSourceAttributes() != nil {
				sourceAttrs[p.Meta.Fqn] = p.Meta.SourceAttributes[namer.PolicyKeyFromFQN(p.Meta.Fqn)]
			}

			if k := util.NewGlobMap(p.Resources).Get(input.Resource.Kind); k != nil {
				mergedActions.Merge(k.Actions)
			}

			activeRoles[r] = struct{}{}
			assumedRoles = append(assumedRoles, r)
			// The role policy implicitly assumes all parent roles
			for _, pr := range p.ParentRoles {
				activeRoles[pr] = struct{}{}
				assumedRoles = append(assumedRoles, pr)
			}
		}

		trail := newAuditTrail(sourceAttrs)
		result := newEvalResult(input.Actions, trail)

		result.AssumedRoles = assumedRoles

		rpctx := tctx.StartRolePolicyScope(input.Resource.Scope)

		actions := util.NewGlobMap(mergedActions)
		for _, a := range input.Actions {
			actx := rpctx.StartAction(a)

			mappingExists := actions.Get(a) != nil
			if mappingExists && scopePermission == policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT {
				result.setEffect(a, EffectInfo{Effect: effectv1.Effect_EFFECT_ALLOW, Scope: input.Principal.Scope})
				actx.AppliedEffect(effectv1.Effect_EFFECT_ALLOW, "")
			} else if !mappingExists {
				result.setEffect(a, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: noMatchScopePermissions, Scope: input.Principal.Scope, ActiveRoles: activeRoles, IsImplicitDeny: true})
				actx.AppliedEffect(effectv1.Effect_EFFECT_DENY, fmt.Sprintf("Resource action pair not defined within role policy for resource %s and action %s", input.Resource.Kind, a))
			}
		}

		result.setDefaultEffect(rpctx, EffectInfo{Effect: effectv1.Effect_EFFECT_NO_MATCH})

		return result, nil
	})
}

type resourcePolicyEvaluator struct {
	policy     *runtimev1.RunnableResourcePolicySet
	schemaMgr  schema.Manager
	evalParams evalParams
}

func (rpe *resourcePolicyEvaluator) Evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	return tracing.RecordSpan2(ctx, "resource_policy.Evaluate", func(ctx context.Context, span trace.Span) (*PolicyEvalResult, error) {
		span.SetAttributes(tracing.PolicyFQN(rpe.policy.Meta.Fqn))

		policyKey := namer.PolicyKeyFromFQN(rpe.policy.Meta.Fqn)
		request := checkInputToRequest(input)
		trail := newAuditTrail(rpe.policy.GetMeta().GetSourceAttributes())
		result := newEvalResult(input.Actions, trail)
		effectiveRoles := internal.ToSet(input.Principal.Roles)

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

			err := tracing.RecordSpan1(ctx, "evaluate_policy", func(ctx context.Context, span trace.Span) error {
				span.SetAttributes(tracing.PolicyScope(p.Scope))
				sctx := pctx.StartScope(p.Scope)
				evalCtx := newEvalContext(rpe.evalParams, request)

				// calculate the set of effective derived roles
				effectiveDerivedRoles := make(internal.StringSet, len(p.DerivedRoles))
				tracing.RecordSpan(ctx, "compute_derived_roles", func(_ context.Context, _ trace.Span) {
					for drName, dr := range p.DerivedRoles {
						dctx := sctx.StartDerivedRole(drName)
						if !internal.SetIntersects(dr.ParentRoles, effectiveRoles) {
							dctx.Skipped(nil, "No matching roles")
							continue
						}

						// evaluate variables of this derived roles set
						drVariables, err := evalCtx.evaluateVariables(dctx.StartVariables(), dr.OrderedVariables)
						if err != nil {
							dctx.Skipped(err, "Error evaluating variables")
							continue
						}

						ok, err := evalCtx.satisfiesCondition(dctx.StartCondition(), dr.Condition, drVariables)
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
				})

				evalCtx = evalCtx.withEffectiveDerivedRoles(effectiveDerivedRoles)

				// evaluate the variables of this policy
				variables, err := tracing.RecordSpan2(ctx, "evaluate_variables", func(_ context.Context, _ trace.Span) (map[string]any, error) {
					return evalCtx.evaluateVariables(sctx.StartVariables(), p.OrderedVariables)
				})
				if err != nil {
					sctx.Failed(err, "Failed to evaluate variables")
					return fmt.Errorf("failed to evaluate variables: %w", err)
				}

				// evaluate each rule until all actions have a result
				tracing.RecordSpan(ctx, "evaluate_rules", func(_ context.Context, _ trace.Span) {
				outer:
					for _, rule := range p.Rules {
						rctx := sctx.StartRule(rule.Name)

						if !internal.SetIntersects(rule.Roles, effectiveRoles) && !internal.SetIntersects(rule.DerivedRoles, evalCtx.effectiveDerivedRoles) {
							rctx.Skipped(nil, "No matching roles or derived roles")
							continue
						}

						ruleActivated := false
						for actionGlob := range rule.Actions {
							matchedActions := util.FilterGlob(actionGlob, actionsToResolve)
							//nolint:dupl
							for _, action := range matchedActions {
								actx := rctx.StartAction(action)
								ok, err := evalCtx.satisfiesCondition(actx.StartCondition(), rule.Condition, variables)
								if err != nil {
									actx.Skipped(err, "Error evaluating condition")
									continue
								}

								if !ok {
									actx.Skipped(nil, "Condition not satisfied")
									if rule.EmitOutput != nil && rule.EmitOutput.When != nil && rule.EmitOutput.When.ConditionNotMet != nil {
										octx := rctx.StartOutput(rule.Name)
										output := &enginev1.OutputEntry{
											Src: namer.RuleFQN(rpe.policy.Meta, p.Scope, rule.Name),
											Val: evalCtx.evaluateProtobufValueCELExpr(rule.EmitOutput.When.ConditionNotMet.Checked, variables),
										}
										result.Outputs = append(result.Outputs, output)
										octx.ComputedOutput(output)
									}
									continue
								}

								if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS && rule.Effect == effectv1.Effect_EFFECT_ALLOW {
									continue outer
								}

								// get intersection
								activeRoles := make(internal.StringSet)
								for r := range rule.Roles {
									if _, ok := effectiveRoles[r]; ok {
										activeRoles[r] = struct{}{}
									}
								}

								result.setEffect(action, EffectInfo{Effect: rule.Effect, Policy: policyKey, Scope: p.Scope, ActiveRoles: activeRoles})
								actx.AppliedEffect(rule.Effect, "")
								ruleActivated = true
							}
						}

						if ruleActivated {
							var outputExpr *exprpb.CheckedExpr
							switch {
							case rule.Output != nil: //nolint:staticcheck
								outputExpr = rule.Output.Checked //nolint:staticcheck
							case rule.EmitOutput != nil && rule.EmitOutput.When != nil && rule.EmitOutput.When.RuleActivated != nil:
								outputExpr = rule.EmitOutput.When.RuleActivated.Checked
							}

							if outputExpr != nil {
								octx := rctx.StartOutput(rule.Name)
								output := &enginev1.OutputEntry{
									Src: namer.RuleFQN(rpe.policy.Meta, p.Scope, rule.Name),
									Val: evalCtx.evaluateProtobufValueCELExpr(outputExpr, variables),
								}
								result.Outputs = append(result.Outputs, output)
								octx.ComputedOutput(output)
							}
						}
					}
				})
				return nil
			})
			if err != nil {
				return nil, err
			}
		}

		// set the default effect for actions that were not matched
		result.setDefaultEffect(pctx, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: policyKey})

		return result, nil
	})
}

type principalPolicyEvaluator struct {
	policy     *runtimev1.RunnablePrincipalPolicySet
	evalParams evalParams
}

func (ppe *principalPolicyEvaluator) Evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	return tracing.RecordSpan2(ctx, "principal_policy.Evaluate", func(ctx context.Context, span trace.Span) (*PolicyEvalResult, error) {
		span.SetAttributes(tracing.PolicyFQN(ppe.policy.Meta.Fqn))

		policyKey := namer.PolicyKeyFromFQN(ppe.policy.Meta.Fqn)
		evalCtx := newEvalContext(ppe.evalParams, checkInputToRequest(input))
		trail := newAuditTrail(ppe.policy.GetMeta().GetSourceAttributes())
		result := newEvalResult(input.Actions, trail)

		pctx := tctx.StartPolicy(ppe.policy.Meta.Fqn)
		for _, p := range ppe.policy.Policies {
			actionsToResolve := result.unresolvedActions()
			if len(actionsToResolve) == 0 {
				return result, nil
			}

			err := tracing.RecordSpan1(ctx, "evalute_policy", func(ctx context.Context, span trace.Span) error {
				span.SetAttributes(tracing.PolicyScope(p.Scope))
				sctx := pctx.StartScope(p.Scope)
				// evaluate the variables of this policy
				variables, err := tracing.RecordSpan2(ctx, "evaluate_variables", func(_ context.Context, _ trace.Span) (map[string]any, error) {
					return evalCtx.evaluateVariables(sctx.StartVariables(), p.OrderedVariables)
				})
				if err != nil {
					sctx.Failed(err, "Failed to evaluate variables")
					return fmt.Errorf("failed to evaluate variables: %w", err)
				}

				tracing.RecordSpan(ctx, "evaluate_rules", func(_ context.Context, _ trace.Span) {
					for resource, resourceRules := range p.ResourceRules {
						rctx := sctx.StartResource(resource)
						if !util.MatchesGlob(resource, input.Resource.Kind) {
							rctx.Skipped(nil, "Did not match input resource kind")
							continue
						}

					outer:
						for _, rule := range resourceRules.ActionRules {
							matchedActions := util.FilterGlob(rule.Action, actionsToResolve)
							ruleActivated := false
							//nolint:dupl
							for _, action := range matchedActions {
								actx := rctx.StartAction(action)
								ok, err := evalCtx.satisfiesCondition(actx.StartCondition(), rule.Condition, variables)
								if err != nil {
									actx.Skipped(err, "Error evaluating condition")
									continue
								}

								if !ok {
									actx.Skipped(nil, "Condition not satisfied")
									if rule.EmitOutput != nil && rule.EmitOutput.When != nil && rule.EmitOutput.When.ConditionNotMet != nil {
										octx := rctx.StartOutput(rule.Name)
										output := &enginev1.OutputEntry{
											Src: namer.RuleFQN(ppe.policy.Meta, p.Scope, rule.Name),
											Val: evalCtx.evaluateProtobufValueCELExpr(rule.EmitOutput.When.ConditionNotMet.Checked, variables),
										}
										result.Outputs = append(result.Outputs, output)
										octx.ComputedOutput(output)
									}
									continue
								}

								if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS && rule.Effect == effectv1.Effect_EFFECT_ALLOW {
									continue outer
								}

								result.setEffect(action, EffectInfo{Effect: rule.Effect, Policy: policyKey, Scope: p.Scope})
								actx.AppliedEffect(rule.Effect, "")
								ruleActivated = true
							}

							if ruleActivated {
								var outputExpr *exprpb.CheckedExpr
								switch {
								case rule.Output != nil: //nolint:staticcheck
									outputExpr = rule.Output.Checked //nolint:staticcheck
								case rule.EmitOutput != nil && rule.EmitOutput.When != nil && rule.EmitOutput.When.RuleActivated != nil:
									outputExpr = rule.EmitOutput.When.RuleActivated.Checked
								}

								if outputExpr != nil {
									var output *enginev1.OutputEntry
									octx := rctx.StartOutput(rule.Name)
									result.Outputs = append(result.Outputs, &enginev1.OutputEntry{
										Src: namer.RuleFQN(ppe.policy.Meta, p.Scope, rule.Name),
										Val: evalCtx.evaluateProtobufValueCELExpr(outputExpr, variables),
									})
									octx.ComputedOutput(output)
								}
							}
						}
					}
				})
				return nil
			})
			if err != nil {
				return nil, err
			}
		}

		result.setDefaultEffect(pctx, EffectInfo{Effect: effectv1.Effect_EFFECT_NO_MATCH})
		return result, nil
	})
}

func (ec *evalContext) evaluateVariables(tctx tracer.Context, variables []*runtimev1.Variable) (map[string]any, error) {
	var errs error
	evalVars := make(map[string]any, len(variables))
	for _, variable := range variables {
		vctx := tctx.StartVariable(variable.Name, variable.Expr.Original)
		val, err := ec.evaluateCELExprToRaw(variable.Expr.Checked, evalVars)
		if err != nil {
			vctx.Skipped(err, "Failed to evaluate expression")
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s := %s`: %w", variable.Name, variable.Expr.Original, err))
			continue
		}

		evalVars[variable.Name] = val
		vctx.ComputedResult(val)
	}

	return evalVars, errs
}

func (ec *evalContext) satisfiesCondition(tctx tracer.Context, cond *runtimev1.Condition, variables map[string]any) (bool, error) {
	if cond == nil {
		tctx.ComputedBoolResult(true, nil, "")
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		ectx := tctx.StartExpr(t.Expr.Original)
		val, err := ec.evaluateBoolCELExpr(t.Expr.Checked, variables)
		if err != nil {
			ectx.ComputedBoolResult(false, err, "Failed to evaluate expression")
			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		ectx.ComputedBoolResult(val, nil, "")
		return val, nil

	case *runtimev1.Condition_All:
		actx := tctx.StartConditionAll()
		for i, expr := range t.All.Expr {
			val, err := ec.satisfiesCondition(actx.StartNthCondition(i), expr, variables)
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
			val, err := ec.satisfiesCondition(actx.StartNthCondition(i), expr, variables)
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
			val, err := ec.satisfiesCondition(actx.StartNthCondition(i), expr, variables)
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

func (ec *evalContext) evaluateBoolCELExpr(expr *exprpb.CheckedExpr, variables map[string]any) (bool, error) {
	val, err := ec.evaluateCELExprToRaw(expr, variables)
	if err != nil {
		return false, err
	}

	if val == nil {
		return false, nil
	}

	boolVal, ok := val.(bool)
	if !ok {
		return false, nil
	}

	return boolVal, nil
}

func (ec *evalContext) evaluateProtobufValueCELExpr(expr *exprpb.CheckedExpr, variables map[string]any) *structpb.Value {
	result, err := ec.evaluateCELExpr(expr, variables)
	if err != nil {
		return structpb.NewStringValue("<failed to evaluate expression>")
	}

	if result == nil {
		return nil
	}

	val, err := result.ConvertToNative(reflect.TypeOf(&structpb.Value{}))
	if err != nil {
		return structpb.NewStringValue("<failed to convert evaluation to protobuf value>")
	}

	pbVal, ok := val.(*structpb.Value)
	if !ok {
		// Something is broken in `ConvertToNative`
		return structpb.NewStringValue("<failed to convert evaluation to protobuf value>")
	}

	return pbVal
}

func (ec *evalContext) evaluateCELExpr(expr *exprpb.CheckedExpr, variables map[string]any) (ref.Val, error) {
	if expr == nil {
		return nil, nil
	}

	result, _, err := conditions.Eval(conditions.StdEnv, cel.CheckedExprToAst(expr), map[string]any{
		conditions.CELRequestIdent:    ec.request,
		conditions.CELResourceAbbrev:  ec.request.Resource,
		conditions.CELPrincipalAbbrev: ec.request.Principal,
		conditions.CELRuntimeIdent:    ec.lazyRuntime,
		conditions.CELVariablesIdent:  variables,
		conditions.CELVariablesAbbrev: variables,
		conditions.CELGlobalsIdent:    ec.globals,
		conditions.CELGlobalsAbbrev:   ec.globals,
	}, ec.nowFunc)
	if err != nil {
		// ignore expressions that are invalid
		if types.IsError(result) {
			return nil, nil
		}

		return nil, err
	}

	return result, nil
}

func (ec *evalContext) evaluateCELExprToRaw(expr *exprpb.CheckedExpr, variables map[string]any) (any, error) {
	result, err := ec.evaluateCELExpr(expr, variables)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, nil
	}

	return result.Value(), nil
}

type EffectInfo struct {
	ActiveRoles    internal.StringSet
	Policy         string
	Scope          string
	Effect         effectv1.Effect
	IsImplicitDeny bool
}

type PolicyEvalResult struct {
	Effects               map[string]EffectInfo
	EffectiveDerivedRoles map[string]struct{}
	toResolve             map[string]struct{}
	AuditTrail            *auditv1.AuditTrail
	ValidationErrors      []*schemav1.ValidationError
	Outputs               []*enginev1.OutputEntry
	AssumedRoles          []string
}

func newEvalResult(actions []string, auditTrail *auditv1.AuditTrail) *PolicyEvalResult {
	per := &PolicyEvalResult{
		Effects:               make(map[string]EffectInfo, len(actions)),
		EffectiveDerivedRoles: make(map[string]struct{}),
		toResolve:             make(map[string]struct{}, len(actions)),
		Outputs:               []*enginev1.OutputEntry{},
		AuditTrail:            auditTrail,
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

func checkInputToRequest(input *enginev1.CheckInput) *enginev1.Request {
	return &enginev1.Request{
		Principal: &enginev1.Request_Principal{
			Id:            input.Principal.Id,
			Roles:         input.Principal.Roles,
			Attr:          input.Principal.Attr,
			PolicyVersion: input.Principal.PolicyVersion,
			Scope:         input.Principal.Scope,
		},
		Resource: &enginev1.Request_Resource{
			Kind:          input.Resource.Kind,
			Id:            input.Resource.Id,
			Attr:          input.Resource.Attr,
			PolicyVersion: input.Resource.PolicyVersion,
			Scope:         input.Resource.Scope,
		},
		AuxData: input.AuxData,
	}
}

func newAuditTrail(srcAttr map[string]*policyv1.SourceAttributes) *auditv1.AuditTrail {
	return &auditv1.AuditTrail{EffectivePolicies: maps.Clone(srcAttr)}
}
