// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"sort"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/engine/internal"
	"github.com/cerbos/cerbos/internal/engine/planner"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/schema"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func EvaluateRuleTableQueryPlan(ctx context.Context, ruleTable *RuleTable, input *enginev1.PlanResourcesInput, schemaMgr schema.Manager, opts *CheckOptions) (*planner.PolicyPlanResult, error) {
	// TODO(saml) reintroduce tracing
	version := input.Resource.PolicyVersion
	if version == "" {
		version = "default"
	}

	scopes, _, _ := ruleTable.GetAllScopes(input.Resource.Scope, input.Resource.Kind, version)

	request := planner.PlanResourcesInputToRequest(input)
	evalCtx := &planner.EvalContext{TimeFn: opts.NowFunc()}

	result := new(planner.PolicyPlanResult)

	fqn := namer.ResourcePolicyFQN(input.Resource.Kind, version, input.Resource.Scope)

	vr, err := schemaMgr.ValidatePlanResourcesInput(ctx, ruleTable.GetSchema(fqn), input)
	if err != nil {
		return nil, fmt.Errorf("failed to validate input: %w", err)
	}
	var validationErrors []*schemav1.ValidationError
	if len(vr.Errors) > 0 {
		validationErrors = vr.Errors.SchemaErrors()

		if vr.Reject {
			result.ValidationErrors = validationErrors
			result.Add(planner.MkTrueNode(), effectv1.Effect_EFFECT_DENY)
			return result, nil
		}
	}

	// Filter down to matching roles and actions
	scanResult := ruleTable.ScanRows(version, namer.SanitizedResource(input.Resource.Kind), scopes, input.Principal.Roles, []string{input.Action})

	var allowNode, denyNode *planner.QpN
	for _, role := range input.Principal.Roles {
		var roleAllowNode, roleDenyNode *planner.QpN
		var scopePermissionsBoundaryOpen bool

		roles := []string{role}
	scopesLoop:
		for _, scope := range scopes {
			var scopeAllowNode, scopeDenyNode *planner.QpN

			// TODO(saml) figure out a more efficient series of filters so we don't have to full scan twice
			scopedScanResult := ruleTable.ScanRows(version, namer.SanitizedResource(input.Resource.Kind), []string{scope}, roles, []string{})
			if len(scopedScanResult.GetRows()) == 0 {
				// the role doesn't exist in this scope for any actions, so continue.
				// this prevents an implicit DENY from incorrectly narrowing an independent role
				continue
			}

			// TODO(saml) make this BETTER. Caching/reuse, whatever
			scopeFqn := namer.ResourcePolicyFQN(input.Resource.Kind, version, scope)
			derivedRolesList := planner.MkDerivedRolesList(nil)
			var derivedRoles []planner.RN
			allRoles := make(map[string]struct{})
			for _, r := range input.Principal.Roles {
				allRoles[r] = struct{}{}
			}
			for _, r := range ruleTable.getParentRoles(input.Principal.Roles) {
				allRoles[r] = struct{}{}
			}
			if drs, ok := ruleTable.policyDerivedRoles[scopeFqn]; ok {
				for name, dr := range drs {
					if !internal.SetIntersects(dr.ParentRoles, allRoles) {
						continue
					}

					constants := planner.ConstantValues(dr.Constants)
					var err error
					variables, err := planner.VariableExprs(dr.OrderedVariables)
					if err != nil {
						return nil, err
					}

					node, err := evalCtx.EvaluateCondition(dr.Condition, request, opts.Globals(), constants, variables, derivedRolesList)
					if err != nil {
						return nil, err
					}

					derivedRoles = append(derivedRoles, planner.RN{
						// TODO(saml) this function was previously memoized. Optimise or refactor out completely
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

			for _, row := range ruleTable.Filter(scanResult, []string{scope}, roles, []string{input.Action}).GetRows() {
				var constants map[string]any
				var variables map[string]*exprpb.Expr
				if row.Parameters != nil {
					constants = planner.ConstantValues(row.Parameters.Constants)
					var err error
					variables, err = planner.VariableExprs(row.Parameters.OrderedVariables)
					if err != nil {
						return nil, err
					}
				}

				node, err := evalCtx.EvaluateCondition(row.Condition, request, opts.Globals(), constants, variables, derivedRolesList)
				if err != nil {
					return nil, err
				}

				switch row.Effect {
				case effectv1.Effect_EFFECT_ALLOW:
					if scopeAllowNode == nil {
						scopeAllowNode = node
					} else {
						scopeAllowNode = planner.MkNodeFromLO(planner.MkOrLogicalOperation([]*planner.QpN{scopeAllowNode, node}))
					}
				case effectv1.Effect_EFFECT_DENY:
					if scopeDenyNode == nil {
						scopeDenyNode = node
					} else {
						scopeDenyNode = planner.MkNodeFromLO(planner.MkOrLogicalOperation([]*planner.QpN{scopeDenyNode, node}))
					}
				}
			}

			if scopeAllowNode != nil {
				if roleAllowNode == nil {
					roleAllowNode = scopeAllowNode
				} else {
					var lo *enginev1.PlanResourcesAst_LogicalOperation
					if scopePermissionsBoundaryOpen {
						lo = planner.MkAndLogicalOperation([]*planner.QpN{roleAllowNode, scopeAllowNode})
						scopePermissionsBoundaryOpen = false
					} else {
						lo = planner.MkOrLogicalOperation([]*planner.QpN{roleAllowNode, scopeAllowNode})
					}
					roleAllowNode = planner.MkNodeFromLO(lo)
				}
			}

			if scopeDenyNode != nil {
				if roleDenyNode == nil {
					roleDenyNode = scopeDenyNode
				} else {
					roleDenyNode = planner.MkNodeFromLO(planner.MkOrLogicalOperation([]*planner.QpN{roleDenyNode, scopeDenyNode}))
				}
			}

			switch ruleTable.GetScopeScopePermissions(scope) {
			case policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS:
				if scopeAllowNode == nil && scopeDenyNode == nil {
					roleDenyNode = planner.MkTrueNode()
					break scopesLoop
				} else if scopeAllowNode != nil && scopeDenyNode == nil {
					scopePermissionsBoundaryOpen = true
				}
			case policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT:
				if scopeAllowNode != nil || scopeDenyNode != nil {
					result.Scope = scope
					break scopesLoop
				}
			}
		}

		// only an ALLOW from a scope with ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS exists with no
		// matching rules in the parent scopes, therefore null the node
		if scopePermissionsBoundaryOpen {
			roleAllowNode = nil
		}

		if allowNode == nil {
			allowNode = roleAllowNode
		}

		if denyNode == nil {
			denyNode = roleDenyNode
		}

		if roleAllowNode != nil {
			break
		}
	}

	if allowNode == nil && denyNode == nil {
		denyNode = planner.MkTrueNode()
	}

	if allowNode != nil {
		result.Add(allowNode, effectv1.Effect_EFFECT_ALLOW)
	}
	if denyNode != nil {
		result.Add(denyNode, effectv1.Effect_EFFECT_DENY)
	}

	return result, nil
}
