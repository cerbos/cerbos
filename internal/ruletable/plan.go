// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"fmt"
	"maps"
	"sort"

	celast "github.com/google/cel-go/common/ast"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/ruletable/internal"
	"github.com/cerbos/cerbos/internal/ruletable/planner"
	"github.com/cerbos/cerbos/internal/schema"
)

func (rt *RuleTable) Plan(ctx context.Context, conf *evaluator.Conf, schemaMgr schema.Manager, input *enginev1.PlanResourcesInput, opts ...evaluator.CheckOpt) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	checkOpts := evaluator.NewCheckOptions(ctx, conf, opts...)

	principalScope := evaluator.Scope(input.Principal.Scope, checkOpts.EvalParams)
	principalVersion := evaluator.PolicyVersion(input.Principal.PolicyVersion, checkOpts.EvalParams)

	resourceScope := evaluator.Scope(input.Resource.Scope, checkOpts.EvalParams)
	resourceVersion := evaluator.PolicyVersion(input.Resource.PolicyVersion, checkOpts.EvalParams)

	return rt.planWithAuditTrail(ctx, schemaMgr, input, principalScope, principalVersion, resourceScope, resourceVersion, checkOpts.NowFunc(), checkOpts.Globals(), checkOpts.LenientScopeSearch())
}

func (rt *RuleTable) planWithAuditTrail(
	ctx context.Context,
	schemaMgr schema.Manager,
	input *enginev1.PlanResourcesInput,
	principalScope, principalVersion, resourceScope, resourceVersion string,
	nowFunc conditions.NowFunc, globals map[string]any, lenientScopeSearch bool,
) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	_, span := tracing.StartSpan(ctx, "engine.Plan")
	defer span.End()

	principalScopes, _, principalPolicyFQN := rt.GetAllScopes(policyv1.Kind_KIND_PRINCIPAL, principalScope, input.Principal.Id, principalVersion, lenientScopeSearch)
	resourceScopes, _, resourcePolicyFQN := rt.GetAllScopes(policyv1.Kind_KIND_RESOURCE, resourceScope, input.Resource.Kind, resourceVersion, lenientScopeSearch)

	effectivePolicies := make(map[string]*policyv1.SourceAttributes)
	auditTrail := &auditv1.AuditTrail{EffectivePolicies: effectivePolicies}

	if len(principalScopes) == 0 && len(resourceScopes) == 0 {
		return noMatchPlanOutput(input, nil), auditTrail, nil
	}

	fqn := resourcePolicyFQN
	if fqn == "" {
		fqn = principalPolicyFQN
	}
	span.SetAttributes(tracing.PolicyFQN(fqn))

	request := planner.PlanResourcesInputToRequest(input)
	evalCtx := &planner.EvalContext{TimeFn: nowFunc}

	filters := make([]*enginev1.PlanResourcesFilter, 0, len(input.Actions))
	matchedScopes := make(map[string]string, len(input.Actions))
	vr, err := schemaMgr.ValidatePlanResourcesInput(ctx, rt.GetSchema(resourcePolicyFQN), input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate input: %w", err)
	}
	var validationErrors []*schemav1.ValidationError
	if len(vr.Errors) > 0 {
		validationErrors = vr.Errors.SchemaErrors()

		if vr.Reject {
			output := planner.MkPlanResourcesOutput(input, nil, validationErrors)
			output.Filter = &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED}
			output.FilterDebug = planner.FilterToString(output.Filter)
			return output, auditTrail, nil
		}
	}

	allRoles := rt.idx.AddParentRoles([]string{resourceScope}, input.Principal.Roles)

	sanitizedResource := namer.SanitizedResource(input.Resource.Kind)

	includingParentRoles := make(map[string]struct{}, len(allRoles))
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	policyMatch := false
	for _, action := range input.Actions {
		matchedScopes[action] = ""
		nf := new(planner.NodeFilter)
		scopedDerivedRolesList := make(map[string]func() (*exprpb.Expr, error))

		var hasPolicyTypeAllow bool
		var rootNode *planner.QpN

		// evaluate resource policies before principal policies
		for _, pt := range []policyv1.Kind{policyv1.Kind_KIND_RESOURCE, policyv1.Kind_KIND_PRINCIPAL} {
			var policyTypeAllowNode, policyTypeDenyNode *planner.QpN

			var scopes []string
			if pt == policyv1.Kind_KIND_PRINCIPAL {
				scopes = principalScopes
			} else {
				scopes = resourceScopes
			}

			for i, role := range input.Principal.Roles {
				// Principal rules are role agnostic (they treat the rows as having a `*` role). Therefore we can
				// break out of the loop after the first iteration as it covers all potential principal rows.
				if i > 0 && pt == policyv1.Kind_KIND_PRINCIPAL {
					break
				}

				var roleAllowNode *planner.QpN
				var roleDenyNode *planner.QpN
				var roleDenyRolePolicyNode *planner.QpN
				var pendingAllow bool

				rolesIncludingParents := rt.idx.AddParentRoles([]string{resourceScope}, []string{role})

				var bindings []*index.Binding
				for _, scope := range scopes {
					var scopeAllowNode *planner.QpN
					var scopeDenyNode *planner.QpN
					var scopeDenyRolePolicyNode *planner.QpN

					derivedRolesList := planner.MkDerivedRolesList(nil)
					if pt == policyv1.Kind_KIND_RESOURCE { //nolint:nestif
						if c, ok := scopedDerivedRolesList[scope]; ok {
							derivedRolesList = c
						} else {
							var derivedRoles []planner.RN
							if drs := rt.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, scope)); drs != nil {
								for name, dr := range drs {
									if !internal.SetIntersects(dr.ParentRoles, includingParentRoles) {
										continue
									}

									var err error
									variables, err := planner.VariableExprs(dr.OrderedVariables)
									if err != nil {
										return nil, auditTrail, err
									}

									node, err := evalCtx.EvaluateCondition(ctx, dr.Condition, request, globals, dr.Constants, variables, derivedRolesList)
									if err != nil {
										return nil, auditTrail, err
									}

									derivedRoles = append(derivedRoles, planner.RN{
										Node: func() (*enginev1.PlanResourcesAst_Node, error) {
											return node, nil
										},
										Role: name,
									})
								}
							}

							sort.Slice(derivedRoles, func(i, j int) bool {
								return derivedRoles[i].Role < derivedRoles[j].Role
							})

							derivedRolesList = planner.MkDerivedRolesList(derivedRoles)

							scopedDerivedRolesList[scope] = derivedRolesList
						}
					}

					// principal ID is only passed for principal policies; for resource
					// policies an empty string means "match all principals".
					var pid string
					if pt == policyv1.Kind_KIND_PRINCIPAL {
						pid = input.Principal.Id
					}
					bindings = rt.idx.Query(resourceVersion, sanitizedResource, scope, action, rolesIncludingParents, pt, pid, bindings[:0])
					for _, b := range bindings {
						if m := rt.GetMeta(b.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
							maps.Copy(effectivePolicies, m.GetSourceAttributes())
						}

						var constants map[string]any
						var variables map[string]celast.Expr
						if b.Core.Params != nil {
							constants = b.Core.Params.Constants
							var err error
							variables, err = planner.VariableExprs(b.Core.Params.Variables)
							if err != nil {
								return nil, auditTrail, err
							}
						}

						node, err := evalCtx.EvaluateCondition(ctx, b.Core.Condition, request, globals, constants, variables, derivedRolesList)
						if err != nil {
							return nil, auditTrail, err
						}

						if b.Core.DerivedRoleCondition != nil { //nolint:nestif
							var variables map[string]celast.Expr
							if b.Core.DerivedRoleParams != nil {
								var err error
								variables, err = planner.VariableExprs(b.Core.DerivedRoleParams.Variables)
								if err != nil {
									return nil, auditTrail, err
								}
							}

							drNode, err := evalCtx.EvaluateCondition(ctx, b.Core.DerivedRoleCondition, request, globals, b.Core.DerivedRoleParams.Constants, variables, derivedRolesList)
							if err != nil {
								return nil, auditTrail, err
							}

							if b.Core.Condition == nil {
								node = drNode
							} else {
								node = planner.MkNodeFromLO(planner.MkAndLogicalOperation([]*planner.QpN{node, drNode}))
							}
						}

						switch b.Core.Effect { //nolint:exhaustive
						case effectv1.Effect_EFFECT_ALLOW:
							scopeAllowNode = addNode(scopeAllowNode, node, planner.MkOrNode)
						case effectv1.Effect_EFFECT_DENY:
							// ignore constant false DENY nodes
							if bv, ok := planner.IsNodeConstBool(node); ok && !bv {
								continue
							}

							if b.Core.FromRolePolicy {
								scopeDenyRolePolicyNode = addNode(scopeDenyRolePolicyNode, node, planner.MkOrNode)
							} else {
								scopeDenyNode = addNode(scopeDenyNode, node, planner.MkOrNode)
							}
						}
					}
					roleDenyNode = addNode(roleDenyNode, scopeDenyNode, planner.MkOrNode)
					roleDenyRolePolicyNode = addNode(roleDenyRolePolicyNode, scopeDenyRolePolicyNode, planner.MkOrNode)

					if scopeAllowNode != nil { //nolint:nestif
						if roleAllowNode == nil {
							roleAllowNode = scopeAllowNode
						} else {
							if pendingAllow {
								roleAllowNode = planner.MkAndNode([]*planner.QpN{roleAllowNode, scopeAllowNode})
								pendingAllow = false
							} else {
								roleAllowNode = planner.MkOrNode([]*planner.QpN{roleAllowNode, scopeAllowNode})
							}
						}

						if rt.GetScopeScopePermissions(scope) == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS {
							pendingAllow = true
						}
					}

					if (scopeDenyNode != nil || scopeDenyRolePolicyNode != nil || scopeAllowNode != nil) &&
						rt.GetScopeScopePermissions(scope) == policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT {
						matchedScopes[action] = scope
					}
				}

				// only an ALLOW from a scope with ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS exists with no
				// matching rules in the parent scopes, therefore null the node
				if pendingAllow {
					roleAllowNode = nil
				}

				// Const DENY overrides any ALLOW in the same role. Check both deny types.
				constTrue := false
				if b, ok := planner.IsNodeConstBool(roleDenyNode); ok && b {
					constTrue = true
				} else if b, ok := planner.IsNodeConstBool(roleDenyRolePolicyNode); ok && b {
					constTrue = true
				}

				if constTrue {
					// Roles are evaluated independently, therefore an ALLOW for one role needs to override a DENY for another.
					// If we pass the role level `DENY==true`, we end up overriding the result for all roles with an `AND(..., NOT(true))`
					// due to the policyTypeDenyNode inversion below. Inverting and resolving in the allow node ensures the role is OR'd
					// against others, e.g. `OR(false, roleAllow1, roleAllow2, ...)`).
					roleAllowNode = planner.MkFalseNode()
					roleDenyNode = nil
					roleDenyRolePolicyNode = nil
				} else if roleAllowNode != nil && roleDenyNode == nil && roleDenyRolePolicyNode == nil {
					if b, ok := planner.IsNodeConstBool(roleAllowNode); ok && b {
						policyTypeAllowNode = roleAllowNode
						policyTypeDenyNode = nil
						// Break out of the roles loop entirely
						break
					}
				}

				// If there is a role policy restriction for this specific role, we must apply it here.
				// An ALLOW from this role is valid ONLY IF it is NOT denied by this role's role policy.
				if roleDenyRolePolicyNode != nil && roleAllowNode != nil {
					roleAllowNode = planner.MkAndNode([]*planner.QpN{
						roleAllowNode,
						planner.InvertNodeBooleanValue(roleDenyRolePolicyNode),
					})
				}

				policyTypeAllowNode = addNode(policyTypeAllowNode, roleAllowNode, planner.MkOrNode)
				policyTypeDenyNode = addNode(policyTypeDenyNode, roleDenyNode, planner.MkOrNode)
			}

			if policyTypeAllowNode != nil {
				hasPolicyTypeAllow = true
			}

			if policyTypeAllowNode != nil {
				if rootNode == nil {
					rootNode = policyTypeAllowNode
				} else {
					rootNode = planner.MkOrNode([]*planner.QpN{policyTypeAllowNode, rootNode})
				}
			}

			// PolicyType denies need to reside at the top level of their PolicyType sub trees (e.g. a conditional
			// DENY in a principal policy needs to be a top level `(NOT deny condition) AND nested ALLOW`), so we
			// invert and AND them as we go.
			if policyTypeDenyNode != nil {
				inv := planner.InvertNodeBooleanValue(policyTypeDenyNode)
				if rootNode == nil {
					rootNode = inv
				} else {
					rootNode = planner.MkAndNode([]*planner.QpN{inv, rootNode})
				}
			}
		}

		if rootNode != nil {
			policyMatch = true
			if !hasPolicyTypeAllow {
				nf.ResetToUnconditionalDeny()
			} else {
				nf.Add(rootNode, effectv1.Effect_EFFECT_ALLOW)
			}
		}

		if nf.AllowIsEmpty() && !nf.DenyIsEmpty() { // reset a conditional DENY to an unconditional one
			nf.ResetToUnconditionalDeny()
		}
		f, err := planner.ToFilter(nf.ToAST())
		if err != nil {
			return nil, nil, err
		}
		filters = append(filters, f)
	} // for each action
	output := planner.MkPlanResourcesOutput(input, matchedScopes, validationErrors)
	output.Filter, output.FilterDebug, err = planner.MergeWithAnd(filters)
	if err != nil {
		return nil, nil, err
	}
	if !policyMatch {
		output.FilterDebug = noPolicyMatch
	}

	return output, auditTrail, nil
}

func noMatchPlanOutput(input *enginev1.PlanResourcesInput, validationErrors []*schemav1.ValidationError) *enginev1.PlanResourcesOutput {
	output := planner.MkPlanResourcesOutput(input, nil, validationErrors)
	output.Filter = &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED}
	output.FilterDebug = noPolicyMatch
	return output
}

func addNode(curr, next *planner.QpN, combine func([]*planner.QpN) *planner.QpN) *planner.QpN {
	if next == nil {
		return curr
	}
	if curr == nil {
		return next
	}
	return combine([]*planner.QpN{curr, next})
}
