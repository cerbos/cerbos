// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"sort"

	"github.com/cerbos/cerbos/internal/conditions/types"
	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/audit"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/ruletable/internal"
	"github.com/cerbos/cerbos/internal/schema"
)

func (rt *RuleTable) Check(ctx context.Context, conf *evaluator.Conf, schemaMgr schema.Manager, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	checkOpts := evaluator.NewCheckOptions(ctx, conf, opts...)
	tctx := tracing.StartTracer(checkOpts.TracerSink)

	// Primary use for this Evaluator interface is the ePDP, so we run the checks synchronously (for now)
	outputs := make([]*enginev1.CheckOutput, len(inputs))
	trail := &auditv1.AuditTrail{}
	for i, input := range inputs {
		out, t, err := rt.checkWithAuditTrail(ctx, tctx, schemaMgr, checkOpts.EvalParams, input)
		if err != nil {
			return nil, nil, err
		}

		outputs[i] = out
		trail = audit.MergeTrails(trail, t)
	}

	return outputs, trail, nil
}

func (rt *RuleTable) checkWithAuditTrail(ctx context.Context, tctx tracer.Context, schemaMgr schema.Manager, evalParams evaluator.EvalParams, input *enginev1.CheckInput) (*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	result, err := rt.check(ctx, tctx, schemaMgr, evalParams, input)
	if err != nil {
		return nil, nil, err
	}

	output := &enginev1.CheckOutput{
		RequestId:  input.RequestId,
		ResourceId: input.Resource.Id,
		Actions:    make(map[string]*enginev1.CheckOutput_ActionEffect, len(input.Actions)),
	}

	// update the output
	for _, action := range input.Actions {
		output.Actions[action] = &enginev1.CheckOutput_ActionEffect{
			Effect: effectv1.Effect_EFFECT_DENY,
			Policy: noPolicyMatch,
		}

		if einfo, ok := result.effects[action]; ok {
			ae := output.Actions[action]
			ae.Effect = einfo.Effect
			ae.Policy = einfo.Policy
			ae.Scope = einfo.Scope
		}
	}

	effectiveDerivedRoles := make([]string, 0, len(result.effectiveDerivedRoles))
	for edr := range result.effectiveDerivedRoles {
		effectiveDerivedRoles = append(effectiveDerivedRoles, edr)
	}
	output.EffectiveDerivedRoles = effectiveDerivedRoles
	output.ValidationErrors = result.validationErrors
	output.Outputs = result.outputs

	return output, result.auditTrail, nil
}

func (rt *RuleTable) check(ctx context.Context, tctx tracer.Context, schemaMgr schema.Manager, evalParams evaluator.EvalParams, input *enginev1.CheckInput) (*policyEvalResult, error) {
	_, span := tracing.StartSpan(ctx, "engine.Check")
	defer span.End()

	principalScope := evaluator.Scope(input.Principal.Scope, evalParams)
	principalVersion := input.Principal.PolicyVersion
	if principalVersion == "" {
		principalVersion = evalParams.DefaultPolicyVersion
	}

	resourceScope := evaluator.Scope(input.Resource.Scope, evalParams)
	resourceVersion := input.Resource.PolicyVersion
	if resourceVersion == "" {
		resourceVersion = evalParams.DefaultPolicyVersion
	}

	trail := newAuditTrail(make(map[string]*policyv1.SourceAttributes))
	result := newEvalResult(input.Actions, trail)

	principalScopes, principalPolicyKey, principalPolicyFQN := rt.GetAllScopes(policyv1.Kind_KIND_PRINCIPAL, principalScope, input.Principal.Id, principalVersion, evalParams.LenientScopeSearch)
	resourceScopes, resourcePolicyKey, resourcePolicyFQN := rt.GetAllScopes(policyv1.Kind_KIND_RESOURCE, resourceScope, input.Resource.Kind, resourceVersion, evalParams.LenientScopeSearch)

	if len(principalScopes) == 0 && len(resourceScopes) == 0 {
		return result, nil
	}

	fqn := resourcePolicyFQN
	if fqn == "" {
		fqn = principalPolicyFQN
	}
	span.SetAttributes(tracing.PolicyFQN(fqn))
	pctx := tctx.StartPolicy(fqn)

	// validate the input
	vr, err := schemaMgr.ValidateCheckInput(ctx, rt.GetSchema(resourcePolicyFQN), input)
	if err != nil {
		pctx.Failed(err, "Error during validation")

		return nil, fmt.Errorf("failed to validate input: %w", err)
	}

	if len(vr.Errors) > 0 {
		result.validationErrors = vr.Errors.SchemaErrors()

		pctx.Failed(vr.Errors, "Validation errors")

		if vr.Reject {
			for _, action := range input.Actions {
				actx := pctx.StartAction(action)

				result.setEffect(action, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: resourcePolicyKey})

				actx.AppliedEffect(effectv1.Effect_EFFECT_DENY, "Rejected due to validation failures")
			}
			return result, nil
		}
	}

	request := checkInputToRequest(input)
	evalCtx := NewEvalContext(evalParams, request, rt.programCache)

	actionsToResolve := result.unresolvedActions()
	if len(actionsToResolve) == 0 {
		return result, nil
	}

	sanitizedResource := namer.SanitizedResource(input.Resource.Kind)
	scopedPrincipalExists, err := rt.idx.ScopedPrincipalExists(principalVersion, principalScopes)
	if err != nil {
		return nil, err
	}
	scopedResourceExists, err := rt.idx.ScopedResourceExists(resourceVersion, sanitizedResource, resourceScopes)
	if err != nil {
		return nil, err
	}

	if !scopedPrincipalExists && !scopedResourceExists {
		return result, nil
	}

	allRoles := rt.idx.AddParentRoles([]string{resourceScope}, input.Principal.Roles)

	includingParentRoles := make(map[string]struct{}, len(allRoles))
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	varCache := make(map[uint64]map[string]any)
	// We can cache evaluated conditions for combinations of parameters and conditions.
	// We use a compound key comprising the parameter origin and the rule FQN.
	conditionCache := make(map[string]bool)

	processedScopedDerivedRoles := make(map[string]struct{})
	policyTypes := []policyv1.Kind{policyv1.Kind_KIND_PRINCIPAL, policyv1.Kind_KIND_RESOURCE}
	for _, action := range actionsToResolve {
		actx := pctx.StartAction(action)

		var actionEffectInfo EffectInfo
		var mainPolicyKey string
		var scopes []string
		for _, pt := range policyTypes {
			if pt == policyv1.Kind_KIND_PRINCIPAL {
				mainPolicyKey = principalPolicyKey
				scopes = principalScopes
			} else {
				mainPolicyKey = resourcePolicyKey
				scopes = resourceScopes
			}

			// Reset `actionEffectInfo` for this policy type with the correct policy key.
			// This ensures we use the right policy name if no rules match
			actionEffectInfo.Effect = effectv1.Effect_EFFECT_NO_MATCH

			for i, role := range input.Principal.Roles {
				// Principal rules are role agnostic (they treat the rows as having a `*` role). Therefore we can
				// break out of the loop after the first iteration as it covers all potential principal rows.
				if i > 0 && pt == policyv1.Kind_KIND_PRINCIPAL {
					break
				}

				var hasAllow bool
				roleEffectInfo := EffectInfo{
					Effect: effectv1.Effect_EFFECT_NO_MATCH,
					Policy: noPolicyMatch,
				}

				// a "policy" exists, regardless of potentially matching rules, so we update the policyKey
				if pt == policyv1.Kind_KIND_RESOURCE && scopedResourceExists ||
					pt == policyv1.Kind_KIND_PRINCIPAL && scopedPrincipalExists {
					roleEffectInfo.Policy = mainPolicyKey
				}

				parentRoles := rt.idx.AddParentRoles([]string{resourceScope}, []string{role})

				var bindings []*index.Binding
			scopesLoop:
				for _, scope := range scopes {
					sctx := actx.StartScope(scope)

					// This is for backwards compatibility with effectiveDerivedRoles.
					// If we reach this point, we can assert that the given {origin policy + scope} combination has been evaluated
					// and therefore we build the effectiveDerivedRoles from those referenced in the policy.
					if pt == policyv1.Kind_KIND_RESOURCE { //nolint:nestif
						if _, ok := processedScopedDerivedRoles[scope]; !ok { //nolint:nestif
							effectiveDerivedRoles := make(internal.StringSet)
							if drs := rt.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, scope)); drs != nil {
								for name, dr := range drs {
									drctx := tctx.StartPolicy(dr.OriginFqn).StartDerivedRole(name)
									if !internal.SetIntersects(dr.ParentRoles, includingParentRoles) {
										drctx.Skipped(nil, "No matching roles")
										continue
									}

									var variables map[string]any
									if c, ok := varCache[dr.VarCacheKey]; ok {
										variables = c
									} else {
										var err error
										variables, err = evalCtx.evaluateVariables(ctx, drctx.StartVariables(), dr.Constants, dr.OrderedVariables)
										if err != nil {
											return nil, err
										}
										varCache[dr.VarCacheKey] = variables
									}

									// we don't use `conditionCache` as we don't do any evaluations scoped solely to derived role conditions
									ok, err := evalCtx.SatisfiesCondition(ctx, drctx.StartCondition(), dr.Condition, dr.Constants, variables)
									if err != nil {
										continue
									}

									if ok {
										effectiveDerivedRoles[name] = struct{}{}
										result.effectiveDerivedRoles[name] = struct{}{}
									}
								}
							}

							evalCtx = evalCtx.withEffectiveDerivedRoles(effectiveDerivedRoles)

							processedScopedDerivedRoles[scope] = struct{}{}
						}
					}

					if roleEffectInfo.Effect != effectv1.Effect_EFFECT_NO_MATCH {
						break
					}

					// principal ID is only passed for principal policies; for resource
					// policies an empty string means "match all principals".
					var pid string
					if pt == policyv1.Kind_KIND_PRINCIPAL {
						pid = input.Principal.Id
					}
					bindings = rt.idx.Query(resourceVersion, sanitizedResource, scope, action, parentRoles, pt, pid, bindings[:0])
					for _, b := range bindings {
						rulectx := sctx.StartRule(b.Name)

						if m := rt.GetMeta(b.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
							maps.Copy(result.auditTrail.EffectivePolicies, m.GetSourceAttributes())
						}

						var constants map[string]any
						var variables map[string]any
						if b.Core.Params != nil {
							constants = b.Core.Params.Constants
							if c, ok := varCache[b.Core.Params.Key]; ok {
								variables = c
							} else {
								var err error
								variables, err = evalCtx.evaluatePrograms(pctx.StartVariables(), constants, b.Core.Params.CelPrograms)
								if err != nil {
									pctx.Skipped(err, "Error evaluating variables")
									return nil, err
								}
								varCache[b.Core.Params.Key] = variables
							}
						}

						var satisfiesCondition bool
						if c, ok := conditionCache[b.EvaluationKey]; ok { //nolint:nestif
							satisfiesCondition = c
						} else {
							// We evaluate the derived role condition (if any) first, as this leads to a more sane engine trace output.
							if b.Core.DerivedRoleCondition != nil {
								drctx := rulectx.StartDerivedRole(b.OriginDerivedRole)
								var derivedRoleConstants map[string]any
								var derivedRoleVariables map[string]any
								if b.Core.DerivedRoleParams != nil {
									derivedRoleConstants = b.Core.DerivedRoleParams.Constants
									if c, ok := varCache[b.Core.DerivedRoleParams.Key]; ok {
										derivedRoleVariables = c
									} else {
										var err error
										derivedRoleVariables, err = evalCtx.evaluatePrograms(drctx.StartVariables(), derivedRoleConstants, b.Core.DerivedRoleParams.CelPrograms)
										if err != nil {
											drctx.Skipped(err, "Error evaluating derived role variables")
											return nil, err
										}
										varCache[b.Core.DerivedRoleParams.Key] = derivedRoleVariables
									}
								}

								// Derived role engine trace logs are handled above. Because derived role conditions are baked into the rule table rows, we don't want to
								// confuse matters by adding condition trace logs if a rule is referencing a derived role, so we pass a no-op context here.
								// TODO(saml) we could probably pre-compile the condition also
								drSatisfied, err := evalCtx.SatisfiesCondition(ctx, tracing.StartTracer(nil), b.Core.DerivedRoleCondition, derivedRoleConstants, derivedRoleVariables)
								if err != nil {
									rulectx.Skipped(err, "Error evaluating derived role condition")
									continue
								}

								// terminate early if the derived role condition isn't satisfied, which is consistent with the pre-rule table implementation
								if !drSatisfied {
									rulectx.Skipped(err, "No matching derived roles")
									conditionCache[b.EvaluationKey] = false
									continue
								}
							}

							isSatisfied, err := evalCtx.SatisfiesCondition(ctx, rulectx.StartCondition(), b.Core.Condition, constants, variables)
							if err != nil {
								rulectx.Skipped(err, "Error evaluating condition")
								continue
							}

							conditionCache[b.EvaluationKey] = isSatisfied
							satisfiesCondition = isSatisfied
						}

						if satisfiesCondition { //nolint:nestif
							var outputExpr *exprpb.CheckedExpr
							if b.Core.EmitOutput != nil && b.Core.EmitOutput.When != nil && b.Core.EmitOutput.When.RuleActivated != nil {
								outputExpr = b.Core.EmitOutput.When.RuleActivated.Checked
							}

							if outputExpr != nil {
								octx := rulectx.StartOutput(b.Name)
								output := &enginev1.OutputEntry{
									Src:    namer.RuleFQN(rt.GetMeta(b.OriginFqn), b.Scope, b.Name),
									Val:    evalCtx.evaluateProtobufValueCELExpr(ctx, outputExpr, b.Core.Params.Constants, variables),
									Action: action,
								}
								result.outputs = append(result.outputs, output)
								octx.ComputedOutput(output)
							}

							if b.Core.Effect == effectv1.Effect_EFFECT_ALLOW {
								hasAllow = true
							}
							if b.Core.Effect == effectv1.Effect_EFFECT_DENY {
								roleEffectInfo.Effect = effectv1.Effect_EFFECT_DENY
								roleEffectInfo.Scope = scope
								if b.Core.FromRolePolicy {
									// Implicit DENY generated as a result of no matching role policy action
									// needs to be attributed to said role policy
									roleEffectInfo.Policy = namer.PolicyKeyFromFQN(b.OriginFqn)
								}
								break scopesLoop
							} else if b.NoMatchForScopePermissions {
								roleEffectInfo.Policy = noMatchScopePermissions
								roleEffectInfo.Scope = scope
							}
						} else {
							if b.Core.EmitOutput != nil && b.Core.EmitOutput.When != nil && b.Core.EmitOutput.When.ConditionNotMet != nil {
								octx := rulectx.StartOutput(b.Name)
								output := &enginev1.OutputEntry{
									Src:    namer.RuleFQN(rt.GetMeta(b.OriginFqn), b.Scope, b.Name),
									Val:    evalCtx.evaluateProtobufValueCELExpr(ctx, b.Core.EmitOutput.When.ConditionNotMet.Checked, b.Core.Params.Constants, variables),
									Action: action,
								}
								result.outputs = append(result.outputs, output)
								octx.ComputedOutput(output)
							}
							rulectx.Skipped(nil, conditionNotSatisfied)
						}
					}

					if hasAllow {
						switch rt.GetScopeScopePermissions(scope) { //nolint:exhaustive
						case policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS:
							hasAllow = false
						case policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT:
							roleEffectInfo.Effect = effectv1.Effect_EFFECT_ALLOW
							roleEffectInfo.Scope = scope
							break scopesLoop
						}
					}
				}

				// Match the first result
				if actionEffectInfo.Effect == effectv1.Effect_EFFECT_NO_MATCH {
					actionEffectInfo = roleEffectInfo
				}

				if roleEffectInfo.Effect == effectv1.Effect_EFFECT_ALLOW {
					// Finalise and return the first independent ALLOW
					actionEffectInfo = roleEffectInfo
					break
				} else if roleEffectInfo.Effect == effectv1.Effect_EFFECT_DENY &&
					actionEffectInfo.Policy == noMatchScopePermissions &&
					roleEffectInfo.Policy != noMatchScopePermissions {
					// Override `noMatchScopePermissions` DENYs with explicit ones for clarity
					actionEffectInfo = roleEffectInfo
				}
			}

			// Skip to next action if this action already has a definitive result from principal policies
			if actionEffectInfo.Effect == effectv1.Effect_EFFECT_ALLOW || actionEffectInfo.Effect == effectv1.Effect_EFFECT_DENY {
				break
			}
		}

		if actionEffectInfo.Effect == effectv1.Effect_EFFECT_NO_MATCH {
			actionEffectInfo.Effect = effectv1.Effect_EFFECT_DENY
		}

		result.setEffect(action, actionEffectInfo)
		actx.AppliedEffect(actionEffectInfo.Effect, "")
	}

	return result, nil
}

type EffectInfo struct {
	Policy string
	Scope  string
	Effect effectv1.Effect
}

type policyEvalResult struct {
	effects               map[string]EffectInfo
	effectiveDerivedRoles map[string]struct{}
	toResolve             map[string]struct{}
	auditTrail            *auditv1.AuditTrail
	validationErrors      []*schemav1.ValidationError
	outputs               []*enginev1.OutputEntry
}

func newEvalResult(actions []string, auditTrail *auditv1.AuditTrail) *policyEvalResult {
	per := &policyEvalResult{
		effects:               make(map[string]EffectInfo, len(actions)),
		effectiveDerivedRoles: make(map[string]struct{}),
		toResolve:             make(map[string]struct{}, len(actions)),
		outputs:               []*enginev1.OutputEntry{},
		auditTrail:            auditTrail,
	}

	for _, a := range actions {
		per.toResolve[a] = struct{}{}
	}

	return per
}

func (er *policyEvalResult) unresolvedActions() []string {
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
func (er *policyEvalResult) setEffect(action string, effect EffectInfo) {
	delete(er.toResolve, action)

	if effect.Effect == effectv1.Effect_EFFECT_DENY {
		er.effects[action] = effect
		return
	}

	current, ok := er.effects[action]
	if !ok {
		er.effects[action] = effect
		return
	}

	if current.Effect != effectv1.Effect_EFFECT_DENY {
		er.effects[action] = effect
	}
}

func newAuditTrail(srcAttr map[string]*policyv1.SourceAttributes) *auditv1.AuditTrail {
	return &auditv1.AuditTrail{EffectivePolicies: maps.Clone(srcAttr)}
}

func checkInputToRequest(input *enginev1.CheckInput) *enginev1.Request {
	return &enginev1.Request{
		Principal: &enginev1.Request_Principal{
			Id:            input.Principal.Id,
			Roles:         input.Principal.Roles,
			Attr:          input.Principal.Attr,
			PolicyVersion: input.Principal.PolicyVersion,
			Scope:         namer.ScopeValue(input.Principal.Scope),
		},
		Resource: &enginev1.Request_Resource{
			Kind:          input.Resource.Kind,
			Id:            input.Resource.Id,
			Attr:          input.Resource.Attr,
			PolicyVersion: input.Resource.PolicyVersion,
			Scope:         namer.ScopeValue(input.Resource.Scope),
		},
		AuxData: input.AuxData,
	}
}

type EvalContext struct {
	request               *enginev1.Request
	runtime               *enginev1.Runtime
	effectiveDerivedRoles internal.StringSet
	programCache          *ProgramCache
	evaluator.EvalParams
}

func NewEvalContext(ep evaluator.EvalParams, request *enginev1.Request, programCache *ProgramCache) *EvalContext {
	return &EvalContext{
		EvalParams:   ep,
		request:      request,
		programCache: programCache,
	}
}

func (ec *EvalContext) withEffectiveDerivedRoles(effectiveDerivedRoles internal.StringSet) *EvalContext {
	return &EvalContext{
		EvalParams:            ec.EvalParams,
		request:               ec.request,
		effectiveDerivedRoles: effectiveDerivedRoles,
		programCache:          ec.programCache,
	}
}

func (ec *EvalContext) lazyRuntime() any { // We have to return `any` rather than `*enginev1.Runtime` here to be able to use this function as a lazy binding in the CEL evaluator.
	if ec.runtime == nil {
		ec.runtime = &enginev1.Runtime{}
		if len(ec.effectiveDerivedRoles) > 0 {
			ec.runtime.EffectiveDerivedRoles = ec.effectiveDerivedRoles.Values()
			sort.Strings(ec.runtime.EffectiveDerivedRoles)
		}
	}

	return ec.runtime
}

func (ec *EvalContext) evaluateVariables(ctx context.Context, tctx tracer.Context, constants map[string]any, variables []*runtimev1.Variable) (map[string]any, error) {
	var errs error
	evalVars := make(map[string]any, len(variables))
	for _, variable := range variables {
		vctx := tctx.StartVariable(variable.Name, variable.Expr.Original)
		val, err := ec.evaluateCELExprToRaw(ctx, variable.Expr.Checked, constants, evalVars)
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

func (ec *EvalContext) buildEvalVars(constants, variables map[string]any) map[string]any {
	return map[string]any{
		conditions.CELRequestIdent:       ec.request,
		conditions.CELResourceAbbrev:     ec.request.Resource,
		conditions.CELPrincipalAbbrev:    ec.request.Principal,
		conditions.CELRuntimeIdent:       ec.lazyRuntime,
		conditions.CELConstantsIdent:     types.VariablesMap(constants),
		conditions.CELConstantsAbbrev:    types.VariablesMap(constants),
		conditions.CELVariablesIdent:     types.VariablesMap(variables),
		conditions.CELVariablesAbbrev:    types.VariablesMap(variables),
		conditions.CELGlobalsIdent:       types.VariablesMap(ec.Globals),
		conditions.CELGlobalsAbbrev:      types.VariablesMap(ec.Globals),
		conditions.CELNowFnActivationKey: ec.NowFunc,
	}
}

func (ec *EvalContext) evaluatePrograms(tctx tracer.Context, constants map[string]any, celPrograms []*index.CelProgram) (map[string]any, error) {
	var errs error

	evalVars := make(map[string]any, len(celPrograms))
	for _, prg := range celPrograms {
		vctx := tctx.StartVariable(prg.Name, prg.Expr)
		result, _, err := prg.Prog.Eval(ec.buildEvalVars(constants, evalVars))
		if err != nil {
			// Ignore errors for expressions that evaluate to an error value (e.g., missing keys).
			// This matches the behavior of evaluateCELExpr which returns nil for such cases.
			if celtypes.IsError(result) {
				vctx.ComputedResult(nil)
				continue
			}
			vctx.Skipped(err, "Failed to evaluate expression")
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s`: %w", prg.Name, err))
			continue
		}

		val := result.Value()
		evalVars[prg.Name] = val
		vctx.ComputedResult(val)
	}

	return evalVars, errs
}

func (ec *EvalContext) SatisfiesCondition(ctx context.Context, tctx tracer.Context, cond *runtimev1.Condition, constants, variables map[string]any) (bool, error) {
	if cond == nil {
		tctx.ComputedBoolResult(true, nil, "")
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		ectx := tctx.StartExpr(t.Expr.Original)
		val, err := ec.evaluateBoolCELExpr(ctx, t.Expr.Checked, constants, variables)
		if err != nil {
			ectx.ComputedBoolResult(false, err, "Failed to evaluate expression")
			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		ectx.ComputedBoolResult(val, nil, "")
		return val, nil

	case *runtimev1.Condition_All:
		actx := tctx.StartConditionAll()
		for i, expr := range t.All.Expr {
			val, err := ec.SatisfiesCondition(ctx, actx.StartNthCondition(i), expr, constants, variables)
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
			val, err := ec.SatisfiesCondition(ctx, actx.StartNthCondition(i), expr, constants, variables)
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
			val, err := ec.SatisfiesCondition(ctx, actx.StartNthCondition(i), expr, constants, variables)
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

func (ec *EvalContext) evaluateBoolCELExpr(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) (bool, error) {
	val, err := ec.evaluateCELExprToRaw(ctx, expr, constants, variables)
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

func (ec *EvalContext) evaluateProtobufValueCELExpr(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) *structpb.Value {
	result, err := ec.evaluateCELExpr(ctx, expr, constants, variables)
	if err != nil {
		return structpb.NewStringValue("<failed to evaluate expression>")
	}

	if result == nil {
		return nil
	}

	val, err := result.ConvertToNative(reflect.TypeFor[*structpb.Value]())
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

func (ec *EvalContext) evaluateCELExpr(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) (ref.Val, error) {
	if expr == nil {
		return nil, nil
	}

	prg, err := ec.programCache.GetOrCreate(expr)
	if err != nil {
		return nil, err
	}

	result, _, err := prg.ContextEval(ctx, ec.buildEvalVars(constants, variables))
	if err != nil {
		// ignore expressions that are invalid
		if celtypes.IsError(result) {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (ec *EvalContext) evaluateCELExprToRaw(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) (any, error) {
	result, err := ec.evaluateCELExpr(ctx, expr, constants, variables)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, nil
	}

	return result.Value(), nil
}
