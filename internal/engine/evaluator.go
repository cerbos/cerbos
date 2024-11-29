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
	case *runtimev1.RunnablePolicySet_RuleTable:
		if len(rp.RuleTable.Rules) == 0 {
			return noopEvaluator{}
		}

		resourceFqn := rp.RuleTable.Rules[0].Fqn
		return &ruleTableEvaluator{
			rules:               rp.RuleTable.Rules,
			parentRoleAncestors: rp.RuleTable.ParentRoleAncestors,
			meta:                rp.RuleTable.Meta[resourceFqn],
			schemas:             rp.RuleTable.Schemas[resourceFqn],
			schemaMgr:           schemaMgr,
			evalParams:          eparams,
		}
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

type ruleTableEvaluator struct {
	rules               []*runtimev1.RuleTable_RuleRow
	parentRoleAncestors map[string]*runtimev1.RuleTable_ParentRoleAncestors
	meta                *runtimev1.RuleTable_Metadata
	schemas             *policyv1.Schemas
	schemaMgr           schema.Manager
	evalParams          evalParams
}

func (rte *ruleTableEvaluator) scanRows(version, resource string, scopes, roles, actions []string) *ruleRowSet {
	res := &ruleRowSet{
		scopeIndex:            make(map[string][]*runtimev1.RuleTable_RuleRow),
		scopeScopePermissions: make(map[string]policyv1.ScopePermissions),
	}

	parentRoleSet := make([]string, 0, len(roles))
	parentRoleMapping := make(map[string]string)
	for _, role := range roles {
		if prs, ok := rte.parentRoleAncestors[role]; ok {
			parentRoleSet = append(parentRoleSet, prs.ParentRoles...)
			for _, pr := range prs.ParentRoles {
				parentRoleMapping[pr] = role
			}
		}
	}

	scopeSet := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = struct{}{}
	}

	for _, row := range rte.rules {
		if version != row.Version {
			continue
		}

		if _, ok := scopeSet[row.Scope]; !ok {
			continue
		}

		if !util.MatchesGlob(row.Resource, resource) {
			continue
		}

		if len(util.FilterGlob(row.Action, actions)) == 0 {
			continue
		}

		if len(util.FilterGlob(row.Role, roles)) == 0 {
			// if the row matched on an assumed parent role, update the role in the row to an arbitrary base role
			// so that we don't need to retrieve parent roles each time we query on the same set of data.
			if len(util.FilterGlob(row.Role, parentRoleSet)) > 0 {
				row.Role = roles[0]
			} else {
				continue
			}
		}

		res.addMatchingRow(row)
	}

	return res
}

func (rrs *ruleRowSet) addMatchingRow(row *runtimev1.RuleTable_RuleRow) {
	rrs.rows = append(rrs.rows, row)

	rrs.scopeIndex[row.Scope] = append(rrs.scopeIndex[row.Scope], row)

	if _, ok := rrs.scopeScopePermissions[row.Scope]; !ok {
		rrs.scopeScopePermissions[row.Scope] = row.ScopePermissions
	}
}

type ruleRowSet struct {
	rows                  []*runtimev1.RuleTable_RuleRow
	scopeIndex            map[string][]*runtimev1.RuleTable_RuleRow
	scopeScopePermissions map[string]policyv1.ScopePermissions
}

func (rrs *ruleRowSet) filter(scopes, roles, actions []string) *ruleRowSet {
	res := &ruleRowSet{
		scopeIndex:            make(map[string][]*runtimev1.RuleTable_RuleRow),
		scopeScopePermissions: make(map[string]policyv1.ScopePermissions),
	}

	for _, s := range scopes {
		if sMap, ok := rrs.scopeIndex[s]; ok {
			for _, row := range sMap {
				if len(util.FilterGlob(row.Action, actions)) > 0 && len(util.FilterGlob(row.Role, roles)) > 0 {
					res.addMatchingRow(row)
				}
			}
		}
	}

	return res
}

type cachedParameters struct {
	constants map[string]any
	variables map[string]any
}

func (rte *ruleTableEvaluator) Evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	policyKey := namer.PolicyKeyFromFQN(rte.meta.Fqn)
	request := checkInputToRequest(input)
	trail := newAuditTrail(rte.meta.GetSourceAttributes())
	result := newEvalResult(input.Actions, trail)

	pctx := tctx.StartPolicy(rte.meta.Fqn)
	evalCtx := newEvalContext(rte.evalParams, request)

	// validate the input
	vr, err := rte.schemaMgr.ValidateCheckInput(ctx, rte.schemas, input)
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

	version := input.Resource.PolicyVersion
	if version == "" {
		version = "default"
	}

	scope := input.Resource.Scope
	scopes := []string{scope}
	for i := len(scope) - 1; i >= 0; i-- {
		if scope[i] == '.' || i == 0 {
			scopes = append(scopes, scope[:i])
		}
	}

	actionsToResolve := result.unresolvedActions()
	if len(actionsToResolve) == 0 {
		return result, nil
	}

	scanResult := rte.scanRows(version, namer.SanitizedResource(input.Resource.Kind), scopes, input.Principal.Roles, actionsToResolve)

	parameterCache := make(map[string]cachedParameters)

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

			roles := []string{role}
			for _, scope := range scopes {
				sctx := roctx.StartScope(scope)

				if roleEffectInfo.Effect != effectv1.Effect_EFFECT_NO_MATCH {
					break
				}

				// TODO(saml) introduce "return 1" functionality to prevent full scans
				scopedScanResult := scanResult.filter([]string{scope}, roles, actionsToResolve)
				if len(scopedScanResult.rows) == 0 {
					// the role doesn't exist in this scope for any actions, so continue.
					// this prevents an implicit DENY from incorrectly narrowing an independent role
					sctx.Skipped(nil, "No matching rules")
					continue
				}

				for _, row := range scopedScanResult.filter([]string{scope}, roles, []string{action}).rows {
					rctx := sctx.StartRule(row.Name)

					var constants, variables map[string]any
					if row.Parameters != nil {
						if c, ok := parameterCache[row.Parameters.Origin]; ok {
							constants = c.constants
							variables = c.variables
						} else {
							constants = constantValues(row.Parameters.Constants)
							var err error
							variables, err = evalCtx.evaluateVariables(tctx.StartVariables(), constants, row.Parameters.OrderedVariables)
							if err != nil {
								rctx.Skipped(err, "Error evaluating variables")
								return nil, err
							}
							parameterCache[row.Parameters.Origin] = cachedParameters{constants, variables}
						}
					}

					ok, err := evalCtx.satisfiesCondition(tctx.StartCondition(), row.Condition, constants, variables)
					if err != nil {
						rctx.Skipped(err, "Error evaluating condition")
						continue
					}

					if ok {
						roleEffectSet[row.Effect] = struct{}{}

						// TODO(saml) behaviour has changed such that we only add an effective derived role if the derived role was activated
						// in a matched rule. I think this makes sense, but perhaps backwards compatibility is necessary here?
						if row.OriginDerivedRole != "" {
							result.EffectiveDerivedRoles[row.OriginDerivedRole] = struct{}{}
						}

						var outputExpr *exprpb.CheckedExpr
						if row.EmitOutput != nil && row.EmitOutput.When != nil && row.EmitOutput.When.RuleActivated != nil {
							outputExpr = row.EmitOutput.When.RuleActivated.Checked
						}

						if outputExpr != nil {
							octx := rctx.StartOutput(row.Name)
							// TODO(saml) ordering of outputs is now not deterministic so some tests now fail (TestCheck/case_21 does sporadically)
							output := &enginev1.OutputEntry{
								Src: namer.RuleFQN(rte.meta, row.Scope, row.Name),
								Val: evalCtx.evaluateProtobufValueCELExpr(outputExpr, constants, variables),
							}
							result.Outputs = append(result.Outputs, output)
							octx.ComputedOutput(output)
						}
					} else {
						if row.EmitOutput != nil && row.EmitOutput.When != nil && row.EmitOutput.When.ConditionNotMet != nil {
							octx := rctx.StartOutput(row.Name)
							output := &enginev1.OutputEntry{
								Src: namer.RuleFQN(rte.meta, row.Scope, row.Name),
								Val: evalCtx.evaluateProtobufValueCELExpr(row.EmitOutput.When.ConditionNotMet.Checked, constants, variables),
							}
							result.Outputs = append(result.Outputs, output)
							octx.ComputedOutput(output)
						}
						rctx.Skipped(nil, "Condition not satisfied")
					}
				}

				switch scanResult.scopeScopePermissions[scope] {
				case policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS:
					if len(roleEffectSet) == 0 {
						roleEffectInfo = EffectInfo{
							Effect: effectv1.Effect_EFFECT_DENY,
							Policy: noMatchScopePermissions,
							Scope:  scope,
						}
					}

					if _, ok := roleEffectSet[effectv1.Effect_EFFECT_ALLOW]; ok {
						delete(roleEffectSet, effectv1.Effect_EFFECT_ALLOW)
					}
				case policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT:
					if len(roleEffectSet) > 0 {
						roleEffectInfo.Scope = scope

						if _, ok := roleEffectSet[effectv1.Effect_EFFECT_DENY]; ok {
							roleEffectInfo.Effect = effectv1.Effect_EFFECT_DENY
						} else {
							roleEffectInfo.Effect = effectv1.Effect_EFFECT_ALLOW
						}

						// explicit ALLOW or DENY for this role, so we can exit the loop
						break
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
		span.SetAttributes(tracing.PolicyScope(input.Resource.Scope))

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
				// TODO(saml) THIS IS WRONG but I'm going to remove this evaluator soon anyway. It's only still here so I can compile
				for _, r := range k.Rules {
					mergedActions.Merge(r.Actions)
				}
			}

			if _, ok := activeRoles[r]; !ok {
				activeRoles[r] = struct{}{}
				assumedRoles = append(assumedRoles, r)
			}
			// The role policy implicitly assumes all parent roles
			for _, pr := range p.ParentRoles {
				if _, ok := activeRoles[pr]; !ok {
					activeRoles[pr] = struct{}{}
					assumedRoles = append(assumedRoles, pr)
				}
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
				result.setEffect(a, EffectInfo{Effect: effectv1.Effect_EFFECT_ALLOW, Scope: input.Resource.Scope, ActiveRoles: activeRoles})
				actx.AppliedEffect(effectv1.Effect_EFFECT_ALLOW, "")
			} else if !mappingExists && scopePermission == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS {
				result.setEffect(a, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: noMatchScopePermissions, Scope: input.Resource.Scope, ActiveRoles: activeRoles})
				actx.AppliedEffect(effectv1.Effect_EFFECT_DENY, fmt.Sprintf("Resource action pair not defined within role policy for resource %s and action %s", input.Resource.Kind, a))
			}
		}

		result.setDefaultEffect(rpctx, EffectInfo{Effect: effectv1.Effect_EFFECT_NO_MATCH, ActiveRoles: activeRoles})

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

			actionsRequiringParentalConsent := make(internal.StringSet)
			accumulatedRolePolicyRoles := make(internal.StringSet)

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

						drConstants := constantValues(dr.Constants)

						// evaluate variables of this derived roles set
						drVariables, err := evalCtx.evaluateVariables(dctx.StartVariables(), drConstants, dr.OrderedVariables)
						if err != nil {
							dctx.Skipped(err, "Error evaluating variables")
							continue
						}

						ok, err := evalCtx.satisfiesCondition(dctx.StartCondition(), dr.Condition, drConstants, drVariables)
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

				constants := constantValues(p.Constants)

				// evaluate the variables of this policy
				variables, err := tracing.RecordSpan2(ctx, "evaluate_variables", func(_ context.Context, _ trace.Span) (map[string]any, error) {
					return evalCtx.evaluateVariables(sctx.StartVariables(), constants, p.OrderedVariables)
				})
				if err != nil {
					sctx.Failed(err, "Failed to evaluate variables")
					return fmt.Errorf("failed to evaluate variables: %w", err)
				}

				// evaluate each rule until all actions have a result
				tracing.RecordSpan(ctx, "evaluate_rules", func(_ context.Context, _ trace.Span) {
					for _, rule := range p.Rules {
						rctx := sctx.StartRule(rule.Name)

						if !internal.SetIntersects(rule.Roles, effectiveRoles) && !internal.SetIntersects(rule.DerivedRoles, evalCtx.effectiveDerivedRoles) {
							rctx.Skipped(nil, "No matching roles or derived roles")
							continue
						}

						if rule.FromRolePolicy {
							for r := range rule.Roles {
								accumulatedRolePolicyRoles[r] = struct{}{}
								effectiveRoles[r] = struct{}{}
							}
						}

						ruleActivated := false
						for actionGlob := range rule.Actions {
							matchedActions := util.FilterGlob(actionGlob, actionsToResolve)
							//nolint:dupl
							for _, action := range matchedActions {
								actx := rctx.StartAction(action)

								// determine whether or not an independent (non-narrowed) role can override
								// an implicit deny for an action.
								if deniedRoles, ok := result.actionImplicitlyDeniedForRoles[action]; ok {
									effectiveMatchedRoles := make(internal.StringSet)
									for rr := range rule.Roles {
										if _, ok := effectiveRoles[rr]; ok {
											effectiveMatchedRoles[rr] = struct{}{}
										}
									}
									for dr := range rule.DerivedRoles {
										if _, ok := evalCtx.effectiveDerivedRoles[dr]; ok {
											if rdr, ok := p.DerivedRoles[dr]; ok {
												for pr := range rdr.ParentRoles {
													effectiveMatchedRoles[pr] = struct{}{}
												}
											}
										}
									}
									if effectiveMatchedRoles.IsSubSetOf(deniedRoles) {
										// all matched roles have been implicitly denied, so skip this action
										continue
									}
								}

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
											Src: namer.RuleFQN(rpe.policy.Meta, p.Scope, rule.Name),
											Val: evalCtx.evaluateProtobufValueCELExpr(rule.EmitOutput.When.ConditionNotMet.Checked, constants, variables),
										}
										result.Outputs = append(result.Outputs, output)
										octx.ComputedOutput(output)
									}
									continue
								}

								if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS && rule.Effect == effectv1.Effect_EFFECT_ALLOW {
									actionsRequiringParentalConsent[action] = struct{}{}
									continue
								}

								result.setEffect(action, EffectInfo{Effect: rule.Effect, Policy: policyKey, Scope: p.Scope})
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
									Val: evalCtx.evaluateProtobufValueCELExpr(outputExpr, constants, variables),
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

			if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS {
				for a := range result.toResolve {
					if _, ok := actionsRequiringParentalConsent[a]; !ok {
						deniedRoles, ok := result.actionImplicitlyDeniedForRoles[a]
						if !ok {
							deniedRoles = make(map[string]struct{})
							result.actionImplicitlyDeniedForRoles[a] = deniedRoles
						}

						for er := range accumulatedRolePolicyRoles {
							deniedRoles[er] = struct{}{}
						}

						result.setEffect(a, EffectInfo{
							Effect:    effectv1.Effect_EFFECT_DENY,
							Policy:    noMatchScopePermissions,
							Scope:     p.Scope,
							isPending: true,
						})
					}
				}
			}
		}

		// set the default effect for actions that were not matched
		result.setDefaultEffect(tctx, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: policyKey})

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

					outer:
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
										Val: evalCtx.evaluateProtobufValueCELExpr(outputExpr, constants, variables),
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

		// result.setDefaultEffect(pctx, EffectInfo{Effect: effectv1.Effect_EFFECT_NO_MATCH})
		return result, nil
	})
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

	result, _, err := conditions.Eval(conditions.StdEnv, cel.CheckedExprToAst(expr), map[string]any{
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
	ActiveRoles internal.StringSet // TODO(saml) this can likely go after the query planner is updated
	Policy      string
	Scope       string
	Effect      effectv1.Effect
	isPending   bool // TODO(saml) remove post query planner update
}

type PolicyEvalResult struct {
	Effects                        map[string]EffectInfo
	EffectiveDerivedRoles          map[string]struct{}
	toResolve                      map[string]struct{}
	actionImplicitlyDeniedForRoles map[string]internal.StringSet // map[{action}]map[{roles}]
	AuditTrail                     *auditv1.AuditTrail
	ValidationErrors               []*schemav1.ValidationError
	Outputs                        []*enginev1.OutputEntry
	AssumedRoles                   []string // TODO(saml) remove once the query planner is updated
}

func newEvalResult(actions []string, auditTrail *auditv1.AuditTrail) *PolicyEvalResult {
	per := &PolicyEvalResult{
		Effects:                        make(map[string]EffectInfo, len(actions)),
		EffectiveDerivedRoles:          make(map[string]struct{}),
		toResolve:                      make(map[string]struct{}, len(actions)),
		actionImplicitlyDeniedForRoles: make(map[string]internal.StringSet),
		Outputs:                        []*enginev1.OutputEntry{},
		AuditTrail:                     auditTrail,
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
	if !effect.isPending {
		delete(er.toResolve, action)
	}

	if effect.Effect == effectv1.Effect_EFFECT_DENY {
		er.Effects[action] = effect
		return
	}

	current, ok := er.Effects[action]
	if !ok {
		er.Effects[action] = effect
		return
	}

	if current.Effect != effectv1.Effect_EFFECT_DENY || current.isPending {
		er.Effects[action] = effect
	}
}

func (er *PolicyEvalResult) setDefaultEffect(tctx tracer.Context, effect EffectInfo) {
	for a := range er.toResolve {
		if _, ok := er.actionImplicitlyDeniedForRoles[a]; ok {
			continue
		}
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

func constantValues(constants map[string]*structpb.Value) map[string]any {
	return (&structpb.Struct{Fields: constants}).AsMap()
}
