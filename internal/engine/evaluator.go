// Copyright 2021-2025 Zenauth Ltd.
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
	"github.com/cerbos/cerbos/internal/engine/ruletable"
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

func NewPrincipalPolicyEvaluator(pps *runtimev1.RunnablePrincipalPolicySet, eparams evalParams) Evaluator {
	if pps == nil || len(pps.Policies) == 0 {
		return noopEvaluator{}
	}

	return &principalPolicyEvaluator{policy: pps, evalParams: eparams}
}

func NewRuleTableEvaluator(rt *ruletable.RuleTable, schemaMgr schema.Manager, eparams evalParams) Evaluator {
	return &ruleTableEvaluator{
		RuleTable:  rt,
		schemaMgr:  schemaMgr,
		evalParams: eparams,
	}
}

type noopEvaluator struct{}

func (noopEvaluator) Evaluate(_ context.Context, _ tracer.Context, _ *enginev1.CheckInput) (*PolicyEvalResult, error) {
	return nil, ErrPolicyNotExecutable
}

type ruleTableEvaluator struct {
	*ruletable.RuleTable
	schemaMgr  schema.Manager
	evalParams evalParams
}

func (rte *ruleTableEvaluator) Evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	version := input.Resource.PolicyVersion
	if version == "" {
		version = rte.evalParams.defaultPolicyVersion
	}

	trail := newAuditTrail(make(map[string]*policyv1.SourceAttributes))
	result := newEvalResult(input.Actions, trail)

	if !rte.ScopeExists(input.Resource.Scope) && !rte.evalParams.lenientScopeSearch {
		return result, nil
	}

	scopes, policyKey, fqn := rte.GetAllScopes(input.Resource.Scope, input.Resource.Kind, version)

	pctx := tctx.StartPolicy(fqn)

	// validate the input
	vr, err := rte.schemaMgr.ValidateCheckInput(ctx, rte.GetSchema(fqn), input)
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

	request := checkInputToRequest(input)
	evalCtx := newEvalContext(rte.evalParams, request)

	actionsToResolve := result.unresolvedActions()
	if len(actionsToResolve) == 0 {
		return result, nil
	}

	sanitizedResource := namer.SanitizedResource(input.Resource.Kind)
	// Return early if no scoped resource policy exists at all
	if !rte.ScopedResourceExists(version, sanitizedResource, scopes) {
		return result, nil
	}

	allRoles := rte.GetParentRoles(input.Resource.Scope, input.Principal.Roles)
	includingParentRoles := make(map[string]struct{})
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	// Filter down to matching roles and actions
	candidateRows := rte.GetRows(version, sanitizedResource, scopes, allRoles, actionsToResolve)

	varCache := make(map[string]map[string]any)
	// We can cache evaluated conditions for combinations of parameters and conditions.
	// We use a compound key comprising the parameter origin and the rule FQN.
	conditionCache := make(map[string]bool)

	processedScopedDerivedRoles := make(map[string]struct{})
	for _, action := range actionsToResolve {
		actx := pctx.StartAction(action)

		var actionEffectInfo EffectInfo
		for _, role := range input.Principal.Roles {
			roctx := actx.StartRole(role)

			roleEffectSet := make(map[effectv1.Effect]struct{})
			roleEffectInfo := EffectInfo{
				Effect: effectv1.Effect_EFFECT_NO_MATCH,
				Policy: policyKey,
			}

			parentRoles := rte.GetParentRoles(input.Resource.Scope, []string{role})

		scopesLoop:
			for _, scope := range scopes {
				sctx := roctx.StartScope(scope)

				// This is for backwards compatibility with effectiveDerivedRoles.
				// If we reach this point, we can assert that the given {origin policy + scope} combination has been evaluated
				// and therefore we build the effectiveDerivedRoles from those referenced in the policy.
				if _, ok := processedScopedDerivedRoles[scope]; !ok { //nolint:nestif
					effectiveDerivedRoles := make(internal.StringSet)
					if drs := rte.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, version, scope)); drs != nil {
						for name, dr := range drs {
							if !internal.SetIntersects(dr.ParentRoles, includingParentRoles) {
								continue
							}

							var variables map[string]any
							key := namer.DerivedRolesFQN(name)
							if c, ok := varCache[key]; ok {
								variables = c
							} else {
								var err error
								variables, err = evalCtx.evaluateVariables(tctx.StartVariables(), dr.Constants, dr.OrderedVariables)
								if err != nil {
									return nil, err
								}
								varCache[key] = variables
							}

							// we don't use `conditionCache` as we don't do any evaluations scoped solely to derived role conditions
							ok, err := evalCtx.satisfiesCondition(tctx.StartCondition(), dr.Condition, dr.Constants, variables)
							if err != nil {
								continue
							}

							if ok {
								effectiveDerivedRoles[name] = struct{}{}
								result.EffectiveDerivedRoles[name] = struct{}{}
							}
						}
					}

					evalCtx = evalCtx.withEffectiveDerivedRoles(effectiveDerivedRoles)

					processedScopedDerivedRoles[scope] = struct{}{}
				}

				if roleEffectInfo.Effect != effectv1.Effect_EFFECT_NO_MATCH {
					break
				}

				var scopedRoleExists bool
				for _, r := range parentRoles {
					if rte.ScopedRoleExists(version, scope, r) {
						scopedRoleExists = true
						break
					}
				}
				if !scopedRoleExists {
					// the role doesn't exist in this scope for any actions, so continue.
					// this prevents an implicit DENY from incorrectly narrowing an independent role
					sctx.Skipped(nil, "No matching rules")
					continue
				}

				for _, row := range candidateRows {
					if !row.Matches(scope, action, parentRoles) {
						continue
					}

					rctx := sctx.StartRule(row.Name)

					if m := rte.GetMeta(row.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
						maps.Copy(result.AuditTrail.EffectivePolicies, m.GetSourceAttributes())
					}

					var constants map[string]any
					var variables map[string]any
					if row.Params != nil {
						constants = row.Params.Constants
						if c, ok := varCache[row.Params.Key]; ok {
							variables = c
						} else {
							var err error
							variables, err = evalCtx.evaluateCELProgramsOrVariables(tctx, constants, row.Params.CelPrograms, row.Params.Variables)
							if err != nil {
								rctx.Skipped(err, "Error evaluating variables")
								return nil, err
							}
							varCache[row.Params.Key] = variables
						}
					}

					var satisfiesCondition bool
					if c, ok := conditionCache[row.EvaluationKey]; ok { //nolint:nestif
						satisfiesCondition = c
					} else {
						isSatisfied, err := evalCtx.satisfiesCondition(tctx.StartCondition(), row.Condition, constants, variables)
						if err != nil {
							rctx.Skipped(err, "Error evaluating condition")
							continue
						}

						// if there's a derived role condition, we need to evaluate that too
						if isSatisfied && row.DerivedRoleCondition != nil {
							var derivedRoleConstants map[string]any
							var derivedRoleVariables map[string]any
							if row.DerivedRoleParams != nil {
								derivedRoleConstants = row.DerivedRoleParams.Constants
								if c, ok := varCache[row.DerivedRoleParams.Key]; ok {
									derivedRoleVariables = c
								} else {
									var err error
									derivedRoleVariables, err = evalCtx.evaluateCELProgramsOrVariables(tctx, derivedRoleConstants, row.DerivedRoleParams.CelPrograms, row.DerivedRoleParams.Variables)
									if err != nil {
										rctx.Skipped(err, "Error evaluating derived role variables")
										return nil, err
									}
									varCache[row.DerivedRoleParams.Key] = derivedRoleVariables
								}
							}

							// TODO(saml) we could probably pre-compile the condition also
							isSatisfied, err = evalCtx.satisfiesCondition(tctx.StartCondition(), row.DerivedRoleCondition, derivedRoleConstants, derivedRoleVariables)
							if err != nil {
								rctx.Skipped(err, "Error evaluating derived role condition")
								continue
							}
						}

						conditionCache[row.EvaluationKey] = isSatisfied
						satisfiesCondition = isSatisfied
					}

					if satisfiesCondition { //nolint:nestif
						roleEffectSet[row.Effect] = struct{}{}

						var outputExpr *exprpb.CheckedExpr
						if row.EmitOutput != nil && row.EmitOutput.When != nil && row.EmitOutput.When.RuleActivated != nil {
							outputExpr = row.EmitOutput.When.RuleActivated.Checked
						}

						if outputExpr != nil {
							octx := rctx.StartOutput(row.Name)
							output := &enginev1.OutputEntry{
								Src: namer.RuleFQN(rte.GetMeta(row.OriginFqn), row.Scope, row.Name),
								Val: evalCtx.evaluateProtobufValueCELExpr(outputExpr, row.Params.Constants, variables),
							}
							result.Outputs = append(result.Outputs, output)
							octx.ComputedOutput(output)
						}
					} else {
						if row.EmitOutput != nil && row.EmitOutput.When != nil && row.EmitOutput.When.ConditionNotMet != nil {
							octx := rctx.StartOutput(row.Name)
							output := &enginev1.OutputEntry{
								Src: namer.RuleFQN(rte.GetMeta(row.OriginFqn), row.Scope, row.Name),
								Val: evalCtx.evaluateProtobufValueCELExpr(row.EmitOutput.When.ConditionNotMet.Checked, row.Params.Constants, variables),
							}
							result.Outputs = append(result.Outputs, output)
							octx.ComputedOutput(output)
						}
						rctx.Skipped(nil, "Condition not satisfied")
					}
				}

				switch rte.GetScopeScopePermissions(scope) { //nolint:exhaustive
				case policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS:
					if len(roleEffectSet) == 0 {
						roleEffectInfo = EffectInfo{
							Effect: effectv1.Effect_EFFECT_DENY,
							Policy: noMatchScopePermissions,
							Scope:  scope,
						}
					}

					delete(roleEffectSet, effectv1.Effect_EFFECT_ALLOW)
				case policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT:
					if len(roleEffectSet) > 0 {
						roleEffectInfo.Scope = scope

						if _, ok := roleEffectSet[effectv1.Effect_EFFECT_DENY]; ok {
							roleEffectInfo.Effect = effectv1.Effect_EFFECT_DENY
						} else {
							roleEffectInfo.Effect = effectv1.Effect_EFFECT_ALLOW
						}

						// explicit ALLOW or DENY for this role, so we can exit the loop
						break scopesLoop
					}
				}
			}

			// Match the first result
			if actionEffectInfo.Effect == effectv1.Effect_EFFECT_UNSPECIFIED {
				actionEffectInfo = roleEffectInfo
			}

			// Finalise and return the first independent ALLOW, if present
			if roleEffectInfo.Effect == effectv1.Effect_EFFECT_ALLOW {
				actionEffectInfo = roleEffectInfo
				break
			}
		}

		if actionEffectInfo.Effect == effectv1.Effect_EFFECT_NO_MATCH {
			actionEffectInfo = EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: policyKey}
		}

		result.setEffect(action, actionEffectInfo)
		actx.AppliedEffect(actionEffectInfo.Effect, "")
	}

	return result, nil
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

		implicitlyAllowedActions := make(map[string]struct{})

		pctx := tctx.StartPolicy(ppe.policy.Meta.Fqn)
		for _, p := range ppe.policy.Policies {
			actionsToResolve := result.unresolvedActions()
			if len(actionsToResolve) == 0 {
				return result, nil
			}

			err := tracing.RecordSpan1(ctx, "evalute_policy", func(ctx context.Context, span trace.Span) error {
				span.SetAttributes(tracing.PolicyScope(p.Scope))
				sctx := pctx.StartScope(p.Scope)

				constants := constantValues(p.Constants)

				// evaluate the variables of this policy
				variables, err := tracing.RecordSpan2(ctx, "evaluate_variables", func(_ context.Context, _ trace.Span) (map[string]any, error) {
					return evalCtx.evaluateVariables(sctx.StartVariables(), constants, p.OrderedVariables)
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

						for _, rule := range resourceRules.ActionRules {
							matchedActions := util.FilterGlob(rule.Action, actionsToResolve)
							ruleActivated := false
							//nolint:dupl
							for _, action := range matchedActions {
								actx := rctx.StartAction(action)
								ok, err := evalCtx.satisfiesCondition(actx.StartCondition(), rule.Condition, constants, variables)
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
											Val: evalCtx.evaluateProtobufValueCELExpr(rule.EmitOutput.When.ConditionNotMet.Checked, constants, variables),
										}
										result.Outputs = append(result.Outputs, output)
										octx.ComputedOutput(output)
									}
									continue
								}

								if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS && rule.Effect == effectv1.Effect_EFFECT_ALLOW {
									implicitlyAllowedActions[action] = struct{}{}
									continue
								}

								delete(implicitlyAllowedActions, action)

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
										Val: evalCtx.evaluateProtobufValueCELExpr(outputExpr, constants, variables),
									})
									octx.ComputedOutput(output)
								}
							}
						}
					}
				})

				if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS {
					for _, a := range result.unresolvedActions() {
						if _, ok := implicitlyAllowedActions[a]; !ok {
							result.setEffect(a, EffectInfo{
								Effect: effectv1.Effect_EFFECT_DENY,
								Policy: noMatchScopePermissions,
								Scope:  p.Scope,
							})
							delete(implicitlyAllowedActions, a)
						}
					}
				}

				return nil
			})
			if err != nil {
				return nil, err
			}
		}

		// Any remaining `implicitlyAllowedActions` had a matching `ALLOW` in the `REQUIRES_PARENTAL_CONSENT` scope but
		// no matching rule in the parent scopes, therefore we issue a `DENY`.
		for action := range implicitlyAllowedActions {
			result.setEffect(action, EffectInfo{
				Effect: effectv1.Effect_EFFECT_DENY,
				Policy: noPolicyMatch,
			})
		}

		return result, nil
	})
}

func (ec *evalContext) evaluateCELProgramsOrVariables(tctx tracer.Context, constants map[string]any, celPrograms []*ruletable.CelProgram, variables []*runtimev1.Variable) (map[string]any, error) {
	// if nowFunc is provided, we need to recompute the cel.Program to handle the custom time decorator, otherwise we can reuse the precomputed program
	// from build-time.
	if ec.nowFunc == nil {
		return ec.evaluatePrograms(constants, celPrograms)
	}

	return ec.evaluateVariables(tctx.StartVariables(), constants, variables)
}

func (ec *evalContext) evaluateVariables(tctx tracer.Context, constants map[string]any, variables []*runtimev1.Variable) (map[string]any, error) {
	var errs error
	evalVars := make(map[string]any, len(variables))
	for _, variable := range variables {
		vctx := tctx.StartVariable(variable.Name, variable.Expr.Original)
		val, err := ec.evaluateCELExprToRaw(variable.Expr.Checked, constants, evalVars)
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

func (ec *evalContext) buildEvalVars(constants, variables map[string]any) map[string]any {
	return map[string]any{
		conditions.CELRequestIdent:    ec.request,
		conditions.CELResourceAbbrev:  ec.request.Resource,
		conditions.CELPrincipalAbbrev: ec.request.Principal,
		conditions.CELRuntimeIdent:    ec.lazyRuntime,
		conditions.CELConstantsIdent:  constants,
		conditions.CELConstantsAbbrev: constants,
		conditions.CELVariablesIdent:  variables,
		conditions.CELVariablesAbbrev: variables,
		conditions.CELGlobalsIdent:    ec.globals,
		conditions.CELGlobalsAbbrev:   ec.globals,
	}
}

func (ec *evalContext) evaluatePrograms(constants map[string]any, celPrograms []*ruletable.CelProgram) (map[string]any, error) {
	var errs error

	evalVars := make(map[string]any, len(celPrograms))
	for _, prg := range celPrograms {
		result, _, err := prg.Prog.Eval(ec.buildEvalVars(constants, evalVars))
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s`: %w", prg.Name, err))
			continue
		}

		evalVars[prg.Name] = result.Value()
	}

	return evalVars, errs
}

func (ec *evalContext) satisfiesCondition(tctx tracer.Context, cond *runtimev1.Condition, constants, variables map[string]any) (bool, error) {
	if cond == nil {
		tctx.ComputedBoolResult(true, nil, "")
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		ectx := tctx.StartExpr(t.Expr.Original)
		val, err := ec.evaluateBoolCELExpr(t.Expr.Checked, constants, variables)
		if err != nil {
			ectx.ComputedBoolResult(false, err, "Failed to evaluate expression")
			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		ectx.ComputedBoolResult(val, nil, "")
		return val, nil

	case *runtimev1.Condition_All:
		actx := tctx.StartConditionAll()
		for i, expr := range t.All.Expr {
			val, err := ec.satisfiesCondition(actx.StartNthCondition(i), expr, constants, variables)
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
			val, err := ec.satisfiesCondition(actx.StartNthCondition(i), expr, constants, variables)
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
			val, err := ec.satisfiesCondition(actx.StartNthCondition(i), expr, constants, variables)
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

func (ec *evalContext) evaluateBoolCELExpr(expr *exprpb.CheckedExpr, constants, variables map[string]any) (bool, error) {
	val, err := ec.evaluateCELExprToRaw(expr, constants, variables)
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

func (ec *evalContext) evaluateProtobufValueCELExpr(expr *exprpb.CheckedExpr, constants, variables map[string]any) *structpb.Value {
	result, err := ec.evaluateCELExpr(expr, constants, variables)
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

func (ec *evalContext) evaluateCELExpr(expr *exprpb.CheckedExpr, constants, variables map[string]any) (ref.Val, error) {
	if expr == nil {
		return nil, nil
	}

	result, _, err := conditions.Eval(conditions.StdEnv, cel.CheckedExprToAst(expr), ec.buildEvalVars(constants, variables), ec.nowFunc)
	if err != nil {
		// ignore expressions that are invalid
		if types.IsError(result) {
			return nil, nil
		}

		return nil, err
	}

	return result, nil
}

func (ec *evalContext) evaluateCELExprToRaw(expr *exprpb.CheckedExpr, constants, variables map[string]any) (any, error) {
	result, err := ec.evaluateCELExpr(expr, constants, variables)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, nil
	}

	return result.Value(), nil
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
	AuditTrail            *auditv1.AuditTrail
	ValidationErrors      []*schemav1.ValidationError
	Outputs               []*enginev1.OutputEntry
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

func constantValues(constants map[string]*structpb.Value) map[string]any {
	return (&structpb.Struct{Fields: constants}).AsMap()
}
