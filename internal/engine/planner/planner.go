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
	"github.com/google/cel-go/checker/decls"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

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
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

type (
	qpN   = enginev1.PlanResourcesAst_Node
	qpNLO = enginev1.PlanResourcesAst_Node_LogicalOperation
	qpNE  = enginev1.PlanResourcesAst_Node_Expression
	rN    = struct {
		Node func() (*qpN, error)
		Role string
	}

	PolicyPlanResult struct {
		EffectivePolicies map[string]*policyv1.SourceAttributes
		Scope             string
		allowFilter       []*qpN
		denyFilter        []*qpN
		ValidationErrors  []*schemav1.ValidationError
		ScopePermissions  policyv1.ScopePermissions
	}
)

type PrincipalPolicyEvaluator struct {
	Policy  *runtimev1.RunnablePrincipalPolicySet
	Globals map[string]any
	NowFn   func() time.Time
}

func CombinePlans(principalPolicyPlan, resourcePolicyPlan *PolicyPlanResult) *PolicyPlanResult {
	if principalPolicyPlan.Empty() {
		return resourcePolicyPlan
	}

	if resourcePolicyPlan.Empty() {
		return principalPolicyPlan
	}

	if resourcePolicyPlan.AllowIsEmpty() && principalPolicyPlan.AllowIsEmpty() {
		return resourcePolicyPlan // short-circuiting
	}

	return &PolicyPlanResult{
		Scope:            fmt.Sprintf("principal: %q; resource: %q", principalPolicyPlan.Scope, resourcePolicyPlan.Scope),
		allowFilter:      append(principalPolicyPlan.allowFilter, resourcePolicyPlan.toAST()),
		denyFilter:       principalPolicyPlan.denyFilter,
		ValidationErrors: resourcePolicyPlan.ValidationErrors, // schemas aren't validated for principal policies
	}
}

func mergePlans(acc, current *PolicyPlanResult) *PolicyPlanResult {
	if acc == nil {
		return current
	}
	scopePermissions := current.ScopePermissions
	allowFilter := current.allowFilter
	if current.AllowIsEmpty() {
		scopePermissions = acc.ScopePermissions
		allowFilter = acc.allowFilter
	} else if !acc.AllowIsEmpty() {
		n := len(acc.allowFilter) * len(current.allowFilter)
		allowFilter = make([]*qpN, 0, n)
		for _, a := range acc.allowFilter {
			for _, c := range current.allowFilter {
				allowFilter = append(allowFilter, mkNodeFromLO(mkAndLogicalOperation([]*qpN{a, c})))
			}
		}
	}
	return &PolicyPlanResult{
		Scope:            current.Scope,
		ScopePermissions: scopePermissions,
		allowFilter:      allowFilter,
		denyFilter:       append(acc.denyFilter, current.denyFilter...),
	}
}

func newPolicyPlanResult(scope string, scopePermissions policyv1.ScopePermissions) *PolicyPlanResult {
	return &PolicyPlanResult{
		Scope:            scope,
		ScopePermissions: scopePermissions,
	}
}

func (p *PolicyPlanResult) add(filter *qpN, effect effectv1.Effect) {
	if effect == effectv1.Effect_EFFECT_ALLOW {
		p.allowFilter = append(p.allowFilter, filter)
	} else {
		p.denyFilter = append(p.denyFilter, invertNodeBooleanValue(filter))
	}
}

func (p *PolicyPlanResult) DenyIsEmpty() bool {
	return len(p.denyFilter) == 0
}

func (p *PolicyPlanResult) AllowIsEmpty() bool {
	return len(p.allowFilter) == 0
}

func (p *PolicyPlanResult) Empty() bool {
	return p.AllowIsEmpty() && p.DenyIsEmpty()
}

func (p *PolicyPlanResult) ToPlanResourcesOutput(input *enginev1.PlanResourcesInput) (*enginev1.PlanResourcesOutput, error) {
	result := &enginev1.PlanResourcesOutput{
		RequestId:        input.RequestId,
		Kind:             input.Resource.Kind,
		PolicyVersion:    input.Resource.PolicyVersion,
		Action:           input.Action,
		Scope:            p.Scope,
		ValidationErrors: p.ValidationErrors,
	}

	var err error
	result.Filter, err = toFilter(p.toAST())
	if err != nil {
		return nil, err
	}

	if input.IncludeMeta {
		result.FilterDebug = filterToString(result.Filter)
	}

	return result, nil
}

func (p *PolicyPlanResult) toAST() *qpN {
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

func (p *PolicyPlanResult) Complete() bool {
	if p == nil {
		return false
	}
	if p.AllowIsEmpty() && !p.DenyIsEmpty() {
		return true
	}
	if !p.Empty() && (p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT || p.Scope == "") { // root scope permissions value is effectively "OVERRIDE_PARENT"
		return true
	}
	return false
}

func (p *PolicyPlanResult) ResetToUnconditionalDeny() {
	p.denyFilter = []*qpN{mkFalseNode()}
}

func (ppe *PrincipalPolicyEvaluator) evalContext() *evalContext {
	return &evalContext{ppe.NowFn}
}

func (ppe *PrincipalPolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.PlanResourcesInput) (acc *PolicyPlanResult, _ error) {
	_, span := tracing.StartSpan(ctx, "principal_policy.EvaluateResourcesQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(ppe.Policy.Meta.Fqn))
	defer span.End()

	derivedRolesList := mkDerivedRolesList(nil)

	request := planResourcesInputToRequest(input)
	var currentResult *PolicyPlanResult
	for _, p := range ppe.Policy.Policies { // there might be more than 1 policy if there are scoped policies
		// if previous iteration has found a matching policy, then quit the loop
		if currentResult.Complete() {
			break
		}
		scopePermissions := p.ScopePermissions
		// for backward compatibility with precompiled bundles need to set default here despite it being set during compilation.
		if scopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
			scopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
		}
		currentResult = newPolicyPlanResult(p.Scope, scopePermissions)

		constants := constantValues(p.Constants)
		variables, err := variableExprs(p.OrderedVariables)
		if err != nil {
			return nil, err
		}

		evalCtx := ppe.evalContext()
		for resource, resourceRules := range p.ResourceRules {
			if !util.MatchesGlob(resource, input.Resource.Kind) {
				continue
			}

			for _, rule := range resourceRules.ActionRules {
				if !matchesActionGlob(rule.Action, input.Action) {
					continue
				}

				filter, err := evalCtx.evaluateCondition(rule.Condition, request, ppe.Globals, constants, variables, derivedRolesList)
				if err != nil {
					return nil, err
				}

				currentResult.add(filter, rule.Effect)
			}
		}
		acc = mergePlans(acc, currentResult)
	}
	return acc, nil
}

func EvaluateRuleTableQueryPlan(ctx context.Context, ruleTable *ruletable.RuleTable, input *enginev1.PlanResourcesInput, policyVersion string, schemaMgr schema.Manager, nowFunc conditions.NowFunc, globals map[string]any) (*PolicyPlanResult, error) {
	fqn := namer.ResourcePolicyFQN(input.Resource.Kind, policyVersion, input.Resource.Scope)

	_, span := tracing.StartSpan(ctx, "rule_table.EvaluateRuleTableQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(fqn))
	defer span.End()

	scopes, _, _ := ruleTable.GetAllScopes(input.Resource.Scope, input.Resource.Kind, policyVersion)

	request := planResourcesInputToRequest(input)
	evalCtx := &evalContext{TimeFn: nowFunc}

	result := &PolicyPlanResult{
		EffectivePolicies: make(map[string]*policyv1.SourceAttributes),
	}

	vr, err := schemaMgr.ValidatePlanResourcesInput(ctx, ruleTable.GetSchema(fqn), input)
	if err != nil {
		return nil, fmt.Errorf("failed to validate input: %w", err)
	}
	var validationErrors []*schemav1.ValidationError
	if len(vr.Errors) > 0 {
		validationErrors = vr.Errors.SchemaErrors()

		if vr.Reject {
			result.ValidationErrors = validationErrors
			result.add(mkTrueNode(), effectv1.Effect_EFFECT_DENY)
			return result, nil
		}
	}

	allRoles := ruleTable.GetParentRoles(input.Principal.Roles)

	// Filter down to matching roles and action
	candidateRows := ruleTable.GetRows(policyVersion, namer.SanitizedResource(input.Resource.Kind), scopes, allRoles, []string{input.Action})

	includingParentRoles := make(map[string]struct{})
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	scopedDerivedRolesList := make(map[string]func() (*exprpb.Expr, error))

	var allowNode, denyNode *qpN
	for _, role := range input.Principal.Roles {
		var roleAllowNode, roleDenyNode *qpN
		var scopePermissionsBoundaryOpen bool

		parentRoles := ruleTable.GetParentRoles([]string{role})

	scopesLoop:
		for _, scope := range scopes {
			var scopeAllowNode, scopeDenyNode *qpN

			var scopedRoleExists bool
			for _, r := range parentRoles {
				if ruleTable.ScopedRoleExists(policyVersion, scope, r) {
					scopedRoleExists = true
					break
				}
			}
			if !scopedRoleExists {
				// the role doesn't exist in this scope for any actions, so continue.
				// this prevents an implicit DENY from incorrectly narrowing an independent role
				continue
			}

			derivedRolesList := mkDerivedRolesList(nil)
			if c, ok := scopedDerivedRolesList[scope]; ok { //nolint:nestif
				derivedRolesList = c
			} else {
				var derivedRoles []rN
				if drs := ruleTable.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, policyVersion, scope)); drs != nil {
					for name, dr := range drs {
						if !internal.SetIntersects(dr.ParentRoles, includingParentRoles) {
							continue
						}

						var err error
						variables, err := variableExprs(dr.OrderedVariables)
						if err != nil {
							return nil, err
						}

						node, err := evalCtx.evaluateCondition(dr.Condition, request, globals, dr.Constants, variables, derivedRolesList)
						if err != nil {
							return nil, err
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

			for _, row := range candidateRows {
				if !row.Matches(scope, input.Action, parentRoles) {
					continue
				}

				if m := ruleTable.GetMeta(row.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
					maps.Copy(result.EffectivePolicies, m.GetSourceAttributes())
				}

				var constants map[string]any
				var variables map[string]celast.Expr
				if row.Params != nil {
					constants = row.Params.Constants
					var err error
					variables, err = variableExprs(row.Params.Variables)
					if err != nil {
						return nil, err
					}
				}

				node, err := evalCtx.evaluateCondition(row.Condition, request, globals, constants, variables, derivedRolesList)
				if err != nil {
					return nil, err
				}

				if row.DerivedRoleCondition != nil { //nolint:nestif
					var variables map[string]celast.Expr
					if row.DerivedRoleParams != nil {
						var err error
						variables, err = variableExprs(row.DerivedRoleParams.Variables)
						if err != nil {
							return nil, err
						}
					}

					drNode, err := evalCtx.evaluateCondition(row.DerivedRoleCondition, request, globals, row.DerivedRoleParams.Constants, variables, derivedRolesList)
					if err != nil {
						return nil, err
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

			if scopeAllowNode != nil { //nolint:nestif
				if roleAllowNode == nil {
					roleAllowNode = scopeAllowNode
				} else {
					var lo *enginev1.PlanResourcesAst_LogicalOperation
					if scopePermissionsBoundaryOpen {
						lo = mkAndLogicalOperation([]*qpN{roleAllowNode, scopeAllowNode})
						scopePermissionsBoundaryOpen = false
					} else {
						lo = mkOrLogicalOperation([]*qpN{roleAllowNode, scopeAllowNode})
					}
					roleAllowNode = mkNodeFromLO(lo)
				}
			}

			if scopeDenyNode != nil {
				if roleDenyNode == nil {
					roleDenyNode = scopeDenyNode
				} else {
					roleDenyNode = mkNodeFromLO(mkOrLogicalOperation([]*qpN{roleDenyNode, scopeDenyNode}))
				}
			}

			switch ruleTable.GetScopeScopePermissions(scope) { //nolint:exhaustive
			case policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS:
				if scopeAllowNode == nil && scopeDenyNode == nil {
					roleDenyNode = mkTrueNode()
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
		denyNode = mkTrueNode()
	}

	if allowNode != nil {
		result.add(allowNode, effectv1.Effect_EFFECT_ALLOW)
	}
	if denyNode != nil {
		result.add(denyNode, effectv1.Effect_EFFECT_DENY)
	}

	result.ValidationErrors = validationErrors
	return result, nil
}

func matchesActionGlob(actionGlob, action string) bool {
	// need to use FilterGlob here so that "*" matches anything
	return len(util.FilterGlob(actionGlob, []string{action})) > 0
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
	lo := &enginev1.PlanResourcesAst_LogicalOperation{
		Operator: enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT,
		Nodes:    []*enginev1.PlanResourcesAst_Node{node},
	}
	return &qpN{Node: &qpNLO{LogicalOperation: lo}}
}

type evalContext struct {
	TimeFn func() time.Time
}

func (evalCtx *evalContext) evaluateCondition(condition *runtimev1.Condition, request *enginev1.Request, globals, constants map[string]any, variables map[string]celast.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*enginev1.PlanResourcesAst_Node, error) {
	if condition == nil {
		return mkTrueNode(), nil
	}

	res := new(qpN)
	switch t := condition.Op.(type) {
	case *runtimev1.Condition_Any:
		nodes := make([]*qpN, 0, len(t.Any.Expr))
		for _, c := range t.Any.Expr {
			node, err := evalCtx.evaluateCondition(c, request, globals, constants, variables, derivedRolesList)
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
			node, err := evalCtx.evaluateCondition(c, request, globals, constants, variables, derivedRolesList)
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
			node, err := evalCtx.evaluateCondition(c, request, globals, constants, variables, derivedRolesList)
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
		residual, err := evalCtx.evaluateConditionExpression(ex, request, globals, constants, variables, derivedRolesList)
		if err != nil {
			return nil, fmt.Errorf("error evaluating condition %q: %w", t.Expr.Original, err)
		}
		res.Node = &qpNE{Expression: residual}
	default:
		return nil, fmt.Errorf("unsupported condition type %T", t)
	}
	return res, nil
}

func (evalCtx *evalContext) evaluateConditionExpression(expr celast.Expr, request *enginev1.Request, globals, constants map[string]any, variables map[string]celast.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*exprpb.CheckedExpr, error) {
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

	val, residual, err := p.evalPartially(e)
	if err != nil {
		// ignore expressions that are invalid
		if types.IsError(val) {
			return conditions.FalseExpr, nil
		}

		return nil, err
	}
	if types.IsUnknown(val) {
		residual, err = p.evalComprehensionBody(residual)
		if err != nil {
			return nil, err
		}
		m := matchers.NewExpressionProcessor()
		var r bool
		r, e, err = m.Process(residual)
		if err != nil {
			return nil, err
		}
		if r {
			_, residual, err = p.evalPartially(e)
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

func (p *partialEvaluator) evalPartially(e celast.Expr) (ref.Val, celast.Expr, error) {
	ast := celast.NewAST(e, nil)
	val, details, err := conditions.Eval(p.env, ast, p.vars, p.nowFn, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		return val, nil, err
	}

	residual, err := residualExpr(ast, details)
	return val, residual, err
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
	ds := make([]*exprpb.Decl, 0, nNameVariants*(len(request.Resource.GetAttr())+1))
	if len(request.Resource.GetAttr()) > 0 {
		for name, value := range request.Resource.Attr {
			for _, s := range conditions.ResourceAttributeNames(name) {
				ds = append(ds, decls.NewVar(s, decls.Dyn))
				knownVars[s] = value
			}
		}
	}
	for _, s := range conditions.ResourceFieldNames(conditions.CELResourceKindField) {
		ds = append(ds, decls.NewVar(s, decls.String))
		knownVars[s] = request.Resource.GetKind()
	}
	env, err = env.Extend(cel.Declarations(ds...))
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

func (p *partialEvaluator) evalComprehensionBody(e celast.Expr) (celast.Expr, error) {
	return evalComprehensionBodyImpl(p.env, p.vars, p.nowFn, e)
}

func evalComprehensionBodyImpl(env *cel.Env, pvars interpreter.PartialActivation, nowFn func() time.Time, e celast.Expr) (celast.Expr, error) {
	if e == nil {
		return nil, nil
	}
	impl := func(e1 celast.Expr) (celast.Expr, error) {
		return evalComprehensionBodyImpl(env, pvars, nowFn, e1)
	}
	fact := celast.NewExprFactory()

	switch e.Kind() {
	case celast.SelectKind:
		sel := e.AsSelect()
		expr, err := impl(sel.Operand())
		if err != nil {
			return nil, err
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
		env1, err := env.Extend(cel.Declarations(decls.NewVar(ce.IterVar(), decls.Dyn)))
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
		_, det, err = conditions.Eval(env1, ast, pvars1, nowFn, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
		if err != nil {
			return nil, err
		}
		le, err = residualExpr(ast, det)
		if err != nil {
			return nil, err
		}
		//loopStep.CallExpr.Args[i] = le
		le, err = evalComprehensionBodyImpl(env1, pvars1, nowFn, le)
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

func residualExpr(ast *celast.AST, details *cel.EvalDetails) (celast.Expr, error) {
	prunedAST := interpreter.PruneAst(ast.Expr(), ast.SourceInfo().MacroCalls(), details.State())
	return prunedAST.Expr(), nil
}

func residualExprProto(a *cel.Ast, details *cel.EvalDetails) (*exprpb.Expr, error) {
	ast := a.NativeRep()
	prunedAST := interpreter.PruneAst(ast.Expr(), ast.SourceInfo().MacroCalls(), details.State())
	return celast.ExprToProto(prunedAST.Expr())
}

func constantValues(constants map[string]*structpb.Value) map[string]any {
	return (&structpb.Struct{Fields: constants}).AsMap()
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
		},
		Resource: &enginev1.Request_Resource{
			Kind: input.Resource.Kind,
			Attr: input.Resource.Attr,
		},
		AuxData: input.AuxData,
	}
}

func replaceRuntimeEffectiveDerivedRoles(expr celast.Expr, derivedRolesList func() (celast.Expr, error)) (celast.Expr, error) {
	return replaceVarsGen2(expr, func(input celast.Expr) (output celast.Expr, matched bool, err error) {
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
	return replaceVarsGen2(expr, func(input celast.Expr) (celast.Expr, bool, error) {
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
