// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
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
	plannerutils "github.com/cerbos/cerbos/internal/engine/planner/internal"
	"github.com/cerbos/cerbos/internal/engine/planner/matchers"
	"github.com/cerbos/cerbos/internal/engine/ruletable"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
)

type (
	qpN   = enginev1.PlanResourcesAst_Node
	qpNLO = enginev1.PlanResourcesAst_Node_LogicalOperation
	qpNE  = enginev1.PlanResourcesAst_Node_Expression
	rN    = struct {
		Node func() (*qpN, error)
		Role string
	}

	nodeFilter struct {
		allowFilter []*qpN
		denyFilter  []*qpN
	}
)

func (p *nodeFilter) add(filter *qpN, effect effectv1.Effect) {
	if effect == effectv1.Effect_EFFECT_ALLOW {
		p.allowFilter = append(p.allowFilter, filter)
	} else {
		p.denyFilter = append(p.denyFilter, invertNodeBooleanValue(filter))
	}
}

func (p *nodeFilter) denyIsEmpty() bool {
	return len(p.denyFilter) == 0
}

func (p *nodeFilter) allowIsEmpty() bool {
	return len(p.allowFilter) == 0
}

func (p *nodeFilter) empty() bool {
	return p.allowIsEmpty() && p.denyIsEmpty()
}

func (p *nodeFilter) resetToUnconditionalDeny() {
	p.denyFilter = []*qpN{mkFalseNode()}
}

func (p *nodeFilter) toAST() *qpN {
	a := len(p.allowFilter)
	d := len(p.denyFilter)

	switch a {
	case 0:
		switch d {
		case 0:
			return mkFalseNode() // default to DENY
		case 1:
			return p.denyFilter[0]
		default:
			return mkNodeFromLO(mkAndLogicalOperation(p.denyFilter))
		}

	case 1:
		if d == 0 {
			return p.allowFilter[0]
		}

		return mkNodeFromLO(mkAndLogicalOperation(append(p.denyFilter, p.allowFilter[0])))

	default:
		allowFilter := mkNodeFromLO(mkOrLogicalOperation(p.allowFilter))

		if d == 0 {
			return allowFilter
		}

		return mkNodeFromLO(mkAndLogicalOperation(append(p.denyFilter, allowFilter)))
	}
}

func mkPlanResourcesOutput(input *enginev1.PlanResourcesInput, scope string, matchedScopes map[string]string, validationErrors []*schemav1.ValidationError) *enginev1.PlanResourcesOutput {
	result := &enginev1.PlanResourcesOutput{
		RequestId:        input.RequestId,
		Kind:             input.Resource.Kind,
		PolicyVersion:    input.Resource.PolicyVersion,
		Actions:          input.Actions,
		Scope: scope,
		MatchedScopes: matchedScopes,
		ValidationErrors: validationErrors,
	}
	return result
}

const noPolicyMatch = "NO_MATCH"

func EvaluateRuleTableQueryPlan(ctx context.Context, ruleTable *ruletable.RuleTable, input *enginev1.PlanResourcesInput, principalVersion, resourceVersion string, schemaMgr schema.Manager, nowFunc conditions.NowFunc, globals map[string]any) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	fqn := namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, input.Resource.Scope)

	_, span := tracing.StartSpan(ctx, "rule_table.EvaluateRuleTableQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(fqn))
	defer span.End()

	principalScopes, _, _ := ruleTable.GetAllScopes(policy.PrincipalKind, input.Principal.Scope, input.Principal.Id, principalVersion)
	resourceScopes, _, _ := ruleTable.GetAllScopes(policy.ResourceKind, input.Resource.Scope, input.Resource.Kind, resourceVersion)

	request := planResourcesInputToRequest(input)
	evalCtx := &evalContext{TimeFn: nowFunc}

	effectivePolicies := make(map[string]*policyv1.SourceAttributes)
	auditTrail := &auditv1.AuditTrail{EffectivePolicies: effectivePolicies}

	filters := make([]*enginev1.PlanResourcesFilter, 0, len(input.Actions))
	matchedScopes := make(map[string]string, len(input.Actions))
	vr, err := schemaMgr.ValidatePlanResourcesInput(ctx, ruleTable.GetSchema(fqn), input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate input: %w", err)
	}
	var validationErrors []*schemav1.ValidationError
	if len(vr.Errors) > 0 {
		validationErrors = vr.Errors.SchemaErrors()

		if vr.Reject {
			output := mkPlanResourcesOutput(input, input.Resource.Scope, validationErrors)
			output.Filter = &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED}
			output.FilterDebug = FilterToString(output.Filter)
			return output, auditTrail, nil
		}
	}

	allRoles := ruleTable.GetParentRoles(input.Resource.Scope, input.Principal.Roles)
	scopes := ruleTable.CombineScopes(principalScopes, resourceScopes)
	candidateRows := ruleTable.GetRows(resourceVersion, namer.SanitizedResource(input.Resource.Kind), scopes, allRoles, input.Actions)
	if len(candidateRows) == 0 {
		output := mkPlanResourcesOutput(input, input.Resource.Scope, validationErrors)
		output.Filter = &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED}
		output.FilterDebug = noPolicyMatch
		return output, auditTrail, nil
	}

	includingParentRoles := make(map[string]struct{})
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	policyMatch := false
	for _, action := range input.Actions {
		nf := new(nodeFilter)
		scopedDerivedRolesList := make(map[string]func() (*exprpb.Expr, error))

		var hasPolicyTypeAllow bool
		var rootNode *qpN

		// evaluate resource policies before principal policies
		for _, pt := range []policy.Kind{policy.ResourceKind, policy.PrincipalKind} {
			var policyTypeAllowNode, policyTypeDenyNode *qpN
			for i, role := range input.Principal.Roles {
				// Principal rules are role agnostic (they treat the rows as having a `*` role). Therefore we can
				// break out of the loop after the first iteration as it covers all potential principal rows.
				if i > 0 && pt == policy.PrincipalKind {
					break
				}

				var roleAllowNode, roleDenyNode *qpN
				var pendingAllow bool

				parentRoles := ruleTable.GetParentRoles(input.Resource.Scope, []string{role})

				for _, scope := range scopes {
					var scopeAllowNode, scopeDenyNode *qpN

					derivedRolesList := mkDerivedRolesList(nil)
					if pt == policy.ResourceKind { //nolint:nestif
						if c, ok := scopedDerivedRolesList[scope]; ok {
							derivedRolesList = c
						} else {
							var derivedRoles []rN
							if drs := ruleTable.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, scope)); drs != nil {
								for name, dr := range drs {
									if !internal.SetIntersects(dr.ParentRoles, includingParentRoles) {
										continue
									}

									var err error
									variables, err := variableExprs(dr.OrderedVariables)
									if err != nil {
										return nil, auditTrail, err
									}

									node, err := evalCtx.evaluateCondition(ctx, dr.Condition, request, globals, dr.Constants, variables, derivedRolesList)
									if err != nil {
										return nil, auditTrail, err
									}

									derivedRoles = append(derivedRoles, rN{
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

							derivedRolesList = mkDerivedRolesList(derivedRoles)

							scopedDerivedRolesList[scope] = derivedRolesList
						}
					}

					for _, row := range candidateRows {
						if ok := row.Matches(pt, scope, action, input.Principal.Id, parentRoles); !ok {
							continue
						}

						if m := ruleTable.GetMeta(row.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
							maps.Copy(effectivePolicies, m.GetSourceAttributes())
						}

						var constants map[string]any
						var variables map[string]celast.Expr
						if row.Params != nil {
							constants = row.Params.Constants
							var err error
							variables, err = variableExprs(row.Params.Variables)
							if err != nil {
								return nil, auditTrail, err
							}
						}

						node, err := evalCtx.evaluateCondition(ctx, row.Condition, request, globals, constants, variables, derivedRolesList)
						if err != nil {
							return nil, auditTrail, err
						}

						if row.DerivedRoleCondition != nil { //nolint:nestif
							var variables map[string]celast.Expr
							if row.DerivedRoleParams != nil {
								var err error
								variables, err = variableExprs(row.DerivedRoleParams.Variables)
								if err != nil {
									return nil, auditTrail, err
								}
							}

							drNode, err := evalCtx.evaluateCondition(ctx, row.DerivedRoleCondition, request, globals, row.DerivedRoleParams.Constants, variables, derivedRolesList)
							if err != nil {
								return nil, auditTrail, err
							}

							if row.Condition == nil {
								node = drNode
							} else {
								node = mkNodeFromLO(mkAndLogicalOperation([]*qpN{node, drNode}))
							}
						}

						switch row.Effect { //nolint:exhaustive
						case effectv1.Effect_EFFECT_ALLOW:
							if scopeAllowNode == nil {
								scopeAllowNode = node
							} else {
								scopeAllowNode = mkNodeFromLO(mkOrLogicalOperation([]*qpN{scopeAllowNode, node}))
							}
						case effectv1.Effect_EFFECT_DENY:
							if scopeDenyNode == nil {
								scopeDenyNode = node
							} else {
								scopeDenyNode = mkNodeFromLO(mkOrLogicalOperation([]*qpN{scopeDenyNode, node}))
							}
						}
					}

					if scopeDenyNode != nil {
						if roleDenyNode == nil {
							roleDenyNode = scopeDenyNode
						} else {
							roleDenyNode = mkNodeFromLO((mkOrLogicalOperation([]*qpN{roleDenyNode, scopeDenyNode})))
						}
					}

					if scopeAllowNode != nil { //nolint:nestif
						if roleAllowNode == nil {
							roleAllowNode = scopeAllowNode
						} else {
							var lo *enginev1.PlanResourcesAst_LogicalOperation
							if pendingAllow {
								lo = mkAndLogicalOperation([]*qpN{roleAllowNode, scopeAllowNode})
								pendingAllow = false
							} else {
								lo = mkOrLogicalOperation([]*qpN{roleAllowNode, scopeAllowNode})
							}
							roleAllowNode = mkNodeFromLO(lo)
						}

						if ruleTable.GetScopeScopePermissions(scope) == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS {
							pendingAllow = true
						}
					}

					if (scopeDenyNode != nil || scopeAllowNode != nil) &&
						ruleTable.GetScopeScopePermissions(scope) == policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT {
						matchedScopes[action] = scope
						break
					}
				}

				// only an ALLOW from a scope with ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS exists with no
				// matching rules in the parent scopes, therefore null the node
				if pendingAllow {
					roleAllowNode = nil
				}

				if roleAllowNode != nil { //nolint:nestif
					// If this role yields an unconditional ALLOW and no DENY, override all denies.
					if roleDenyNode == nil {
						if b, ok := isNodeConstBool(roleAllowNode); ok && b {
							policyTypeAllowNode = roleAllowNode
							policyTypeDenyNode = nil
							break
						}
					}

					if policyTypeAllowNode == nil {
						policyTypeAllowNode = roleAllowNode
					} else {
						policyTypeAllowNode = mkNodeFromLO(mkOrLogicalOperation([]*qpN{policyTypeAllowNode, roleAllowNode}))
					}
				}

				if roleDenyNode != nil {
					if policyTypeDenyNode == nil {
						policyTypeDenyNode = roleDenyNode
					} else {
						policyTypeDenyNode = mkNodeFromLO(mkOrLogicalOperation([]*qpN{policyTypeDenyNode, roleDenyNode}))
					}
				}
			}

			if policyTypeAllowNode != nil {
				hasPolicyTypeAllow = true
			}

			if policyTypeAllowNode != nil {
				if rootNode == nil {
					rootNode = policyTypeAllowNode
				} else {
					rootNode = mkNodeFromLO(mkOrLogicalOperation([]*qpN{policyTypeAllowNode, rootNode}))
				}
			}

			// PolicyType denies need to reside at the top level of their PolicyType sub trees (e.g. a conditional
			// DENY in a principal policy needs to be a top level `(NOT deny condition) AND nested ALLOW`), so we
			// invert and AND them as we go.
			if policyTypeDenyNode != nil {
				inv := invertNodeBooleanValue(policyTypeDenyNode)
				if rootNode == nil {
					rootNode = inv
				} else {
					rootNode = mkNodeFromLO(mkAndLogicalOperation([]*qpN{inv, rootNode}))
				}
			}
		}

		if rootNode != nil {
			policyMatch = true
			if !hasPolicyTypeAllow {
				nf.resetToUnconditionalDeny()
			} else {
				nf.add(rootNode, effectv1.Effect_EFFECT_ALLOW)
			}
		}

		if nf.allowIsEmpty() && !nf.denyIsEmpty() { // reset an conditional DENY to an unconditional one
			nf.resetToUnconditionalDeny()
		}
		f, err := toFilter(nf.toAST())
		if err != nil {
			return nil, nil, err
		}
		filters = append(filters, f)
	} // for each action
	output := mkPlanResourcesOutput(input, matchedScopes, validationErrors)
	output.Filter, output.FilterDebug, err = MergeWithAnd(filters)
	if err != nil {
		return nil, nil, err
	}
	if !policyMatch {
		output.FilterDebug = noPolicyMatch
	}

	return output, auditTrail, nil
}

func isNodeConstBool(node *enginev1.PlanResourcesAst_Node) (bool, bool) {
	if e, ok := node.Node.(*enginev1.PlanResourcesAst_Node_Expression); ok {
		if e1 := e.Expression.GetExpr().GetConstExpr(); e1 != nil {
			if b, ok := e1.ConstantKind.(*exprpb.Constant_BoolValue); ok {
				return b.BoolValue, true
			}
		}
	}

	return false, false
}

func mkNodeFromLO(lo *enginev1.PlanResourcesAst_LogicalOperation) *enginev1.PlanResourcesAst_Node {
	// node AND drNode
	return &qpN{Node: &qpNLO{LogicalOperation: lo}}
}

func mkOrLogicalOperation(nodes []*enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_LogicalOperation {
	return &enginev1.PlanResourcesAst_LogicalOperation{
		Operator: enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_OR,
		Nodes:    nodes,
	}
}

func mkAndLogicalOperation(nodes []*enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_LogicalOperation {
	return &enginev1.PlanResourcesAst_LogicalOperation{
		Operator: enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_AND,
		Nodes:    nodes,
	}
}

func mkFalseNode() *enginev1.PlanResourcesAst_Node {
	return &qpN{Node: &qpNE{Expression: conditions.FalseExpr}}
}

func mkTrueNode() *enginev1.PlanResourcesAst_Node {
	return &qpN{Node: &qpNE{Expression: conditions.TrueExpr}}
}

func invertNodeBooleanValue(node *enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_Node {
	if lo, ok := node.Node.(*enginev1.PlanResourcesAst_Node_LogicalOperation); ok {
		// No point NOT'ing a NOT. Therefore strip the existing NOT operator
		if lo.LogicalOperation.Operator == enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT {
			nodes := lo.LogicalOperation.GetNodes()
			switch len(nodes) {
			case 1:
				return lo.LogicalOperation.GetNodes()[0]
			default:
				return mkNodeFromLO(mkAndLogicalOperation(nodes))
			}
		}
	}

	lo := &enginev1.PlanResourcesAst_LogicalOperation{
		Operator: enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT,
		Nodes:    []*enginev1.PlanResourcesAst_Node{node},
	}
	return &qpN{Node: &qpNLO{LogicalOperation: lo}}
}

type evalContext struct {
	TimeFn func() time.Time
}

func (evalCtx *evalContext) evaluateCondition(ctx context.Context, condition *runtimev1.Condition, request *enginev1.Request, globals, constants map[string]any, variables map[string]celast.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*enginev1.PlanResourcesAst_Node, error) {
	if condition == nil {
		return mkTrueNode(), nil
	}

	res := new(qpN)
	switch t := condition.Op.(type) {
	case *runtimev1.Condition_Any:
		nodes := make([]*qpN, 0, len(t.Any.Expr))
		for _, c := range t.Any.Expr {
			node, err := evalCtx.evaluateCondition(ctx, c, request, globals, constants, variables, derivedRolesList)
			if err != nil {
				return nil, err
			}

			if b, ok := isNodeConstBool(node); ok {
				if b {
					return mkTrueNode(), nil
				}
			} else {
				nodes = append(nodes, node)
			}
		}
		switch len(nodes) {
		case 0:
			res.Node = &qpNE{Expression: conditions.FalseExpr}
		case 1:
			res.Node = nodes[0].Node
		default:
			res.Node = &qpNLO{LogicalOperation: mkOrLogicalOperation(nodes)}
		}
	case *runtimev1.Condition_All:
		nodes := make([]*qpN, 0, len(t.All.Expr))
		for _, c := range t.All.Expr {
			node, err := evalCtx.evaluateCondition(ctx, c, request, globals, constants, variables, derivedRolesList)
			if err != nil {
				return nil, err
			}
			if b, ok := isNodeConstBool(node); ok {
				if !b {
					return mkFalseNode(), nil
				}
			} else {
				nodes = append(nodes, node)
			}
		}
		switch len(nodes) {
		case 0:
			res.Node = &qpNE{Expression: conditions.TrueExpr}
		case 1:
			res.Node = nodes[0].Node
		default:
			res.Node = &qpNLO{LogicalOperation: mkAndLogicalOperation(nodes)}
		}
	case *runtimev1.Condition_None:
		nodes := make([]*qpN, 0, len(t.None.Expr))
		for _, c := range t.None.Expr {
			node, err := evalCtx.evaluateCondition(ctx, c, request, globals, constants, variables, derivedRolesList)
			if err != nil {
				return nil, err
			}
			add := true

			if b, ok := isNodeConstBool(node); ok {
				if b {
					res.Node = &qpNE{Expression: conditions.FalseExpr}
					return res, nil
				}
				add = false
			}

			if add {
				nodes = append(nodes, invertNodeBooleanValue(node))
			}
		}
		switch len(nodes) {
		case 0:
			res.Node = &qpNE{Expression: conditions.TrueExpr}
		case 1:
			res.Node = nodes[0].Node
		default:
			res.Node = &qpNLO{LogicalOperation: mkAndLogicalOperation(nodes)}
		}
	case *runtimev1.Condition_Expr:
		expr := t.Expr.GetChecked().GetExpr()
		ex, err := celast.ProtoToExpr(expr)
		if err != nil {
			return nil, fmt.Errorf("celast.ProtoToExpr: %w", err)
		}
		residual, err := evalCtx.evaluateConditionExpression(ctx, ex, request, globals, constants, variables, derivedRolesList)
		if err != nil {
			return nil, fmt.Errorf("error evaluating condition %q: %w", t.Expr.Original, err)
		}
		res.Node = &qpNE{Expression: residual}
	default:
		return nil, fmt.Errorf("unsupported condition type %T", t)
	}
	return res, nil
}

func (evalCtx *evalContext) evaluateConditionExpression(ctx context.Context, expr celast.Expr, request *enginev1.Request, globals, constants map[string]any, variables map[string]celast.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*exprpb.CheckedExpr, error) {
	p, err := evalCtx.newEvaluator(request, globals, constants)
	if err != nil {
		return nil, err
	}

	e, err := replaceVars(expr, variables)
	if err != nil {
		return nil, err
	}

	if m := request.Resource.GetAttr(); len(m) > 0 {
		e, err = replaceResourceVals(e, m)
		if err != nil {
			return nil, err
		}
	}

	e, err = replaceRuntimeEffectiveDerivedRoles(e, func() (celast.Expr, error) {
		expr, err := derivedRolesList()
		if err != nil {
			return nil, err
		}
		return celast.ProtoToExpr(expr)
	})
	if err != nil {
		return nil, err
	}

	e, err = replaceCamelCaseFields(e)
	if err != nil {
		return nil, err
	}

	val, residual, err := p.evalPartially(ctx, e)
	if err != nil {
		// ignore expressions that are invalid
		if types.IsError(val) {
			return conditions.FalseExpr, nil
		}

		return nil, err
	}
	if types.IsUnknown(val) {
		return p.evaluateUnknown(ctx, residual)
	}

	expr2, err := celast.ExprToProto(residual)
	if err != nil {
		return nil, fmt.Errorf("error converting expression to proto: %w", err)
	}
	if _, ok := val.Value().(bool); ok {
		return &exprpb.CheckedExpr{Expr: expr2}, nil
	}

	return conditions.FalseExpr, nil
}

type partialEvaluator struct {
	env   *cel.Env
	vars  interpreter.PartialActivation
	nowFn func() time.Time
}

func (p *partialEvaluator) evaluateUnknown(ctx context.Context, residual celast.Expr) (_ *exprpb.CheckedExpr, err error) {
	residual, err = p.evalComprehensionBody(ctx, residual)
	if err != nil {
		return nil, err
	}
	m := matchers.NewExpressionProcessor()
	var r bool
	var e celast.Expr
	r, e, err = m.Process(residual)
	if err != nil {
		return nil, err
	}
	if r {
		_, residual, err = p.evalPartially(ctx, e)
		if err != nil {
			return nil, err
		}
	}

	expr2, err := celast.ExprToProto(residual)
	if err != nil {
		return nil, fmt.Errorf("error converting expression to proto: %w", err)
	}
	return &exprpb.CheckedExpr{Expr: expr2}, nil
}

func (p *partialEvaluator) evalPartially(ctx context.Context, e celast.Expr) (ref.Val, celast.Expr, error) {
	ast := celast.NewAST(e, nil)
	val, details, err := conditions.ContextEval(ctx, p.env, ast, p.vars, p.nowFn, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		return val, nil, err
	}

	return val, residualExpr(ast, details), err
}

func newPartialEvaluator(env *cel.Env, vars interpreter.PartialActivation, nowFn func() time.Time) *partialEvaluator {
	return &partialEvaluator{env, vars, nowFn}
}

func (evalCtx *evalContext) newEvaluator(request *enginev1.Request, globals, constants map[string]any) (p *partialEvaluator, err error) {
	knownVars := make(map[string]any)
	knownVars[conditions.CELRequestIdent] = request
	knownVars[conditions.CELPrincipalAbbrev] = request.Principal
	knownVars[conditions.CELGlobalsIdent] = globals
	knownVars[conditions.CELGlobalsAbbrev] = globals
	knownVars[conditions.CELConstantsIdent] = constants
	knownVars[conditions.CELConstantsAbbrev] = constants

	env := conditions.StdEnv

	const nNameVariants = 2 // qualified, unqualified name
	ds := make([]*decls.VariableDecl, 0, nNameVariants*(len(request.Resource.GetAttr())+1))
	if len(request.Resource.GetAttr()) > 0 {
		reg, err := types.NewRegistry()
		if err != nil {
			return nil, err
		}
		structVal := structpb.Struct{Fields: request.Resource.GetAttr()}
		m := types.NewJSONStruct(reg, &structVal)
		for name := range request.Resource.Attr {
			value := m.Get(types.String(name))
			for _, s := range conditions.ResourceAttributeNames(name) {
				ds = append(ds, decls.NewVariable(s, types.DynType))
				knownVars[s] = value
			}
		}
	}
	for _, s := range conditions.ResourceFieldNames(conditions.CELResourceKindField) {
		ds = append(ds, decls.NewVariable(s, types.StringType))
		knownVars[s] = request.Resource.GetKind()
	}
	for _, s := range conditions.ResourceFieldNames(conditions.CELScopeField) {
		ds = append(ds, decls.NewVariable(s, types.StringType))
		knownVars[s] = request.Resource.GetScope()
	}
	for _, s := range conditions.PrincipalFieldNames(conditions.CELScopeField) {
		ds = append(ds, decls.NewVariable(s, types.StringType))
		knownVars[s] = request.Principal.GetScope()
	}
	env, err = env.Extend(cel.VariableDecls(ds...))
	if err != nil {
		return nil, err
	}

	vars, err := cel.PartialVars(knownVars,
		cel.AttributePattern(conditions.CELResourceAbbrev),
		cel.AttributePattern(conditions.CELRequestIdent).QualString(conditions.CELResourceField))
	if err != nil {
		return nil, err
	}

	return newPartialEvaluator(env, vars, evalCtx.TimeFn), nil
}

func (p *partialEvaluator) evalComprehensionBody(ctx context.Context, e celast.Expr) (celast.Expr, error) {
	return evalComprehensionBodyImpl(ctx, p.env, p.vars, p.nowFn, e)
}

func evalComprehensionBodyImpl(ctx context.Context, env *cel.Env, pvars interpreter.PartialActivation, nowFn func() time.Time, e celast.Expr) (celast.Expr, error) {
	if e == nil {
		return nil, nil
	}
	impl := func(e1 celast.Expr) (celast.Expr, error) {
		return evalComprehensionBodyImpl(ctx, env, pvars, nowFn, e1)
	}
	fact := celast.NewExprFactory()

	switch e.Kind() {
	case celast.SelectKind:
		sel := e.AsSelect()
		expr, err := impl(sel.Operand())
		if err != nil {
			return nil, err
		}
		if sel.IsTestOnly() {
			return fact.NewPresenceTest(0, expr, sel.FieldName()), nil
		}
		return fact.NewSelect(0, expr, sel.FieldName()), nil
	case celast.CallKind:
		call := e.AsCall()
		args := make([]celast.Expr, 0, len(call.Args()))
		for _, arg := range call.Args() {
			expr, err := impl(arg)
			if err != nil {
				return nil, err
			}
			args = append(args, expr)
		}
		if call.IsMemberFunction() {
			target, err := impl(call.Target())
			if err != nil {
				return nil, err
			}
			return fact.NewMemberCall(0, call.FunctionName(), target, args...), nil
		}
		return fact.NewCall(0, call.FunctionName(), args...), nil
	case celast.StructKind:
		st := e.AsStruct()
		flds := make([]celast.EntryExpr, 0, len(st.Fields()))
		for _, entry := range st.Fields() {
			expr, err := impl(entry.AsStructField().Value())
			if err != nil {
				return nil, err
			}
			flds = append(flds, fact.NewStructField(0, entry.AsStructField().Name(), expr, entry.AsStructField().IsOptional()))
		}
		return fact.NewStruct(0, st.TypeName(), flds), nil
	case celast.MapKind:
		m := e.AsMap()
		entries := make([]celast.EntryExpr, 0, len(m.Entries()))
		for _, entry := range m.Entries() {
			k, err := impl(entry.AsMapEntry().Key())
			if err != nil {
				return nil, err
			}
			v, err := impl(entry.AsMapEntry().Value())
			if err != nil {
				return nil, err
			}
			entries = append(entries, fact.NewMapEntry(0, k, v, entry.AsMapEntry().IsOptional()))
		}
		return fact.NewMap(0, entries), nil
	case celast.ComprehensionKind:
		ce := e.AsComprehension()
		if ce.LoopStep().Kind() != celast.CallKind {
			return nil, errors.New("expected call expr")
		}
		loopStep := ce.LoopStep().AsCall()
		var i int
		args := make([]celast.Expr, len(loopStep.Args()))
		copy(args, loopStep.Args())
		if args[i].AsIdent() == ce.AccuVar() {
			i++
		}
		le := args[i]
		env1, err := env.Extend(cel.VariableDecls(decls.NewVariable(ce.IterVar(), types.DynType)))
		if err != nil {
			return nil, err
		}
		le.RenumberIDs(plannerutils.NewIDGen().Remap)
		ast := celast.NewAST(le, nil)

		unknowns := append(pvars.UnknownAttributePatterns(), cel.AttributePattern(ce.IterVar()))
		var pvars1 interpreter.PartialActivation
		pvars1, err = cel.PartialVars(pvars, unknowns...)
		if err != nil {
			return nil, err
		}
		var det *cel.EvalDetails
		_, det, err = conditions.ContextEval(ctx, env1, ast, pvars1, nowFn, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
		if err != nil {
			return nil, err
		}
		le = residualExpr(ast, det)
		le, err = evalComprehensionBodyImpl(ctx, env1, pvars1, nowFn, le)
		if err != nil {
			return nil, err
		}
		args[i] = le
		loopStep1 := fact.NewCall(0, loopStep.FunctionName(), args...)
		ir, err := impl(ce.IterRange())
		if err != nil {
			return nil, err
		}
		if ce.IterVar2() == "" {
			return fact.NewComprehension(0, ir, ce.IterVar(), ce.AccuVar(), ce.AccuInit(), ce.LoopCondition(), loopStep1, ce.Result()), nil
		}
		return fact.NewComprehensionTwoVar(0, ir, ce.IterVar(), ce.IterVar2(), ce.AccuVar(), ce.AccuInit(), ce.LoopCondition(), loopStep1, ce.Result()), nil
	case celast.ListKind:
		lst := e.AsList()
		elmts := make([]celast.Expr, 0, len(lst.Elements()))
		for _, element := range e.AsList().Elements() {
			expr, err := impl(element)
			if err != nil {
				return nil, err
			}
			elmts = append(elmts, expr)
		}
		return fact.NewList(0, elmts, lst.OptionalIndices()), nil
	default:
		return fact.CopyExpr(e), nil
	}
}

func residualExpr(ast *celast.AST, details *cel.EvalDetails) celast.Expr {
	prunedAST := interpreter.PruneAst(ast.Expr(), ast.SourceInfo().MacroCalls(), details.State())
	return prunedAST.Expr()
}

func variableExprs(variables []*runtimev1.Variable) (map[string]celast.Expr, error) {
	if len(variables) == 0 {
		return nil, nil
	}

	exprs := make(map[string]celast.Expr, len(variables))
	for _, variable := range variables {
		e, err := celast.ProtoToExpr(variable.Expr.GetChecked().GetExpr())
		if err != nil {
			return nil, err
		}
		expr, err := replaceVars(e, exprs)
		if err != nil {
			return nil, err
		}

		exprs[variable.Name] = expr
	}

	return exprs, nil
}

func planResourcesInputToRequest(input *enginev1.PlanResourcesInput) *enginev1.Request {
	return &enginev1.Request{
		Principal: &enginev1.Request_Principal{
			Id:    input.Principal.Id,
			Roles: input.Principal.Roles,
			Attr:  input.Principal.Attr,
			Scope: input.Principal.Scope,
		},
		Resource: &enginev1.Request_Resource{
			Kind:  input.Resource.Kind,
			Attr:  input.Resource.Attr,
			Scope: input.Resource.Scope,
		},
		AuxData: input.AuxData,
	}
}

func replaceRuntimeEffectiveDerivedRoles(expr celast.Expr, derivedRolesList func() (celast.Expr, error)) (celast.Expr, error) {
	return replaceVarsGen(expr, func(input celast.Expr) (output celast.Expr, matched bool, err error) {
		se := input.AsSelect()
		if input.Kind() != celast.SelectKind {
			return nil, false, nil
		}

		if isRuntimeEffectiveDerivedRoles(se) {
			output, err = derivedRolesList()
			return output, true, err
		}

		return nil, false, nil
	})
}

func isRuntimeEffectiveDerivedRoles(expr celast.SelectExpr) bool {
	ident := expr.Operand().AsIdent()

	return expr.Operand().Kind() == celast.IdentKind &&
		ident == conditions.CELRuntimeIdent &&
		(expr.FieldName() == "effective_derived_roles" || expr.FieldName() == "effectiveDerivedRoles")
}

func mkDerivedRolesList(derivedRoles []rN) func() (*exprpb.Expr, error) {
	return memoize(func() (_ *exprpb.Expr, err error) {
		switch len(derivedRoles) {
		case 0:
			return plannerutils.MkListExprProto(nil), nil

		case 1:
			return derivedRoleListElement(derivedRoles[0])

		default:
			elements := make([]*exprpb.Expr, len(derivedRoles))
			for i, derivedRole := range derivedRoles {
				elements[i], err = derivedRoleListElement(derivedRole)
				if err != nil {
					return nil, err
				}
			}

			return mkBinaryOperatorExpr(operators.Add, elements...), nil
		}
	})
}

func mkBinaryOperatorExpr(op string, args ...*exprpb.Expr) *exprpb.Expr {
	const arity = 2
	if len(args) == arity {
		return plannerutils.MkCallExprProto(op, args[0], args[1])
	}

	return plannerutils.MkCallExprProto(op, args[0], mkBinaryOperatorExpr(op, args[1:]...))
}

func derivedRoleListElement(derivedRole rN) (*exprpb.Expr, error) {
	conditionNode, err := derivedRole.Node()
	if err != nil {
		return nil, err
	}

	conditionExpr, err := qpNToExpr(conditionNode)
	if err != nil {
		return nil, err
	}

	return plannerutils.MkCallExprProto(
		operators.Conditional,
		conditionExpr,
		plannerutils.MkListExprProto([]*exprpb.Expr{mkConstStringExpr(derivedRole.Role)}),
		plannerutils.MkListExprProto(nil),
	), nil
}

func qpNToExpr(node *qpN) (*exprpb.Expr, error) {
	switch n := node.Node.(type) {
	case *enginev1.PlanResourcesAst_Node_Expression:
		return n.Expression.Expr, nil

	case *enginev1.PlanResourcesAst_Node_LogicalOperation:
		var op string
		switch n.LogicalOperation.Operator {
		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT:
			arg, err := qpNToExpr(n.LogicalOperation.Nodes[0])
			if err != nil {
				return nil, err
			}
			return plannerutils.MkCallExprProto(operators.LogicalNot, arg), nil

		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_AND:
			op = operators.LogicalAnd

		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_OR:
			op = operators.LogicalOr

		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_UNSPECIFIED:
			return nil, errors.New("unspecified logical operator")
		}

		args := make([]*exprpb.Expr, len(n.LogicalOperation.Nodes))
		for i, arg := range n.LogicalOperation.Nodes {
			var err error
			args[i], err = qpNToExpr(arg)
			if err != nil {
				return nil, err
			}
		}

		return mkBinaryOperatorExpr(op, args...), nil
	}

	return nil, fmt.Errorf("unknown node type %T", node.Node)
}

func memoize[T any](f func() (T, error)) func() (T, error) {
	var result T
	var err error
	memoized := false

	return func() (T, error) {
		if memoized {
			return result, err
		}

		result, err = f()
		memoized = true
		return result, err
	}
}

func replaceCamelCaseFields(expr celast.Expr) (celast.Expr, error) {
	// For some reason, the JSONFieldProvider is ignored in the planner. It _should_ work, and I haven't been able to work out why it doesn't.
	// For now, work around the issue by rewriting camel case fields to snake case.
	// We don't need to rewrite `runtime.effectiveDerivedRoles`, because that is handled in replaceRuntimeEffectiveDerivedRoles.
	return replaceVarsGen(expr, func(input celast.Expr) (celast.Expr, bool, error) {
		if input.Kind() != celast.SelectKind {
			return nil, false, nil
		}
		sel := input.AsSelect()
		ident := sel.Operand().AsIdent()

		if sel.Operand().Kind() == celast.IdentKind && ident == conditions.CELRequestIdent && sel.FieldName() == "auxData" {
			fact := celast.NewExprFactory()
			return fact.NewSelect(0, sel.Operand(), "aux_data"), true, nil
		}

		return nil, false, nil
	})
}
