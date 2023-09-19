// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/internal"
	plannerutils "github.com/cerbos/cerbos/internal/engine/planner/internal"
	"github.com/cerbos/cerbos/internal/engine/planner/matchers"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

type (
	qpN   = enginev1.PlanResourcesAst_Node
	qpNLO = enginev1.PlanResourcesAst_Node_LogicalOperation
	qpNE  = enginev1.PlanResourcesAst_Node_Expression
	rN    = struct {
		node func() (*qpN, error)
		role string
	}

	PolicyPlanResult struct {
		Scope            string
		AllowFilter      []*qpN
		DenyFilter       []*qpN
		ValidationErrors []*schemav1.ValidationError
	}
)

type ResourcePolicyEvaluator struct {
	Policy    *runtimev1.RunnableResourcePolicySet
	Globals   map[string]any
	SchemaMgr schema.Manager
}

type PrincipalPolicyEvaluator struct {
	Policy  *runtimev1.RunnablePrincipalPolicySet
	Globals map[string]any
}

func CombinePlans(principalPolicyPlan, resourcePolicyPlan *PolicyPlanResult) *PolicyPlanResult {
	if principalPolicyPlan.Empty() {
		return resourcePolicyPlan
	}

	if resourcePolicyPlan.Empty() {
		return principalPolicyPlan
	}

	return &PolicyPlanResult{
		Scope:            fmt.Sprintf("principal: %q; resource: %q", principalPolicyPlan.Scope, resourcePolicyPlan.Scope),
		AllowFilter:      append(principalPolicyPlan.AllowFilter, resourcePolicyPlan.toAST()),
		DenyFilter:       principalPolicyPlan.DenyFilter,
		ValidationErrors: resourcePolicyPlan.ValidationErrors, // schemas aren't validated for principal policies
	}
}

func (p *PolicyPlanResult) Add(filter *qpN, effect effectv1.Effect) {
	if effect == effectv1.Effect_EFFECT_ALLOW {
		p.AllowFilter = append(p.AllowFilter, filter)
	} else {
		p.DenyFilter = append(p.DenyFilter, invertNodeBooleanValue(filter))
	}
}

func (p *PolicyPlanResult) Empty() bool {
	return len(p.AllowFilter) == 0 && len(p.DenyFilter) == 0
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
	a := len(p.AllowFilter)
	d := len(p.DenyFilter)

	switch a {
	case 0:
		switch d {
		case 0:
			return mkFalseNode() // default to DENY
		case 1:
			return p.DenyFilter[0]
		default:
			return mkNodeFromLO(mkAndLogicalOperation(p.DenyFilter))
		}

	case 1:
		if d == 0 {
			return p.AllowFilter[0]
		}

		return mkNodeFromLO(mkAndLogicalOperation(append(p.DenyFilter, p.AllowFilter[0])))

	default:
		allowFilter := mkNodeFromLO(mkOrLogicalOperation(p.AllowFilter))

		if d == 0 {
			return allowFilter
		}

		return mkNodeFromLO(mkAndLogicalOperation(append(p.DenyFilter, allowFilter)))
	}
}

func (ppe *PrincipalPolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.PlanResourcesInput) (*PolicyPlanResult, error) {
	_, span := tracing.StartSpan(ctx, "principal_policy.EvaluateResourcesQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(ppe.Policy.Meta.Fqn))
	defer span.End()

	derivedRolesList := mkDerivedRolesList(nil)

	request := planResourcesInputToRequest(input)
	result := &PolicyPlanResult{}
	for _, p := range ppe.Policy.Policies { // there might be more than 1 policy if there are scoped policies
		// if previous iteration has found a matching policy, then quit the loop
		if !result.Empty() {
			break
		}

		variables, err := variableExprs(p.OrderedVariables)
		if err != nil {
			return nil, err
		}

		result.Scope = p.Scope
		for resource, resourceRules := range p.ResourceRules {
			if !util.MatchesGlob(resource, input.Resource.Kind) {
				continue
			}

			for _, rule := range resourceRules.ActionRules {
				if !matchesActionGlob(rule.Action, input.Action) {
					continue
				}

				filter, err := evaluateCondition(rule.Condition, request, ppe.Globals, variables, derivedRolesList)
				if err != nil {
					return nil, err
				}

				result.Add(filter, rule.Effect)
			}
		}
	}

	return result, nil
}

func (rpe *ResourcePolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.PlanResourcesInput) (*PolicyPlanResult, error) {
	_, span := tracing.StartSpan(ctx, "resource_policy.EvaluateResourcesQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(rpe.Policy.Meta.Fqn))
	defer span.End()

	request := planResourcesInputToRequest(input)
	result := &PolicyPlanResult{}

	vr, err := rpe.SchemaMgr.ValidatePlanResourcesInput(ctx, rpe.Policy.Schemas, input)
	if err != nil {
		return nil, fmt.Errorf("failed to validate input: %w", err)
	}

	if len(vr.Errors) > 0 {
		result.ValidationErrors = vr.Errors.SchemaErrors()

		if vr.Reject {
			result.Add(mkTrueNode(), effectv1.Effect_EFFECT_DENY)
			return result, nil
		}
	}

	effectiveRoles := internal.ToSet(input.Principal.Roles)

	for _, p := range rpe.Policy.Policies { // there might be more than 1 policy if there are scoped policies
		// if previous iteration has found a matching policy, then quit the loop
		if !result.Empty() {
			break
		}

		variables, err := variableExprs(p.OrderedVariables)
		if err != nil {
			return nil, err
		}

		result.Scope = p.Scope

		var derivedRoles []rN

		derivedRolesList := mkDerivedRolesList(nil)

		for drName, dr := range p.DerivedRoles {
			dr := dr
			if !internal.SetIntersects(dr.ParentRoles, effectiveRoles) {
				continue
			}

			drVariables, err := variableExprs(dr.OrderedVariables)
			if err != nil {
				return nil, err
			}

			derivedRoles = append(derivedRoles, rN{
				role: drName,
				node: memoize(func() (*qpN, error) {
					if dr.Condition == nil {
						return mkTrueNode(), nil
					}
					node, err := evaluateCondition(dr.Condition, request, rpe.Globals, drVariables, derivedRolesList)
					if err != nil {
						return nil, err
					}
					return node, nil
				}),
			})
		}

		sort.Slice(derivedRoles, func(i, j int) bool {
			return derivedRoles[i].role < derivedRoles[j].role
		})

		derivedRolesList = mkDerivedRolesList(derivedRoles)

		for _, rule := range p.Rules {
			var drNode *qpN
			if !internal.SetIntersects(rule.Roles, effectiveRoles) {
				nodes, err := getDerivedRoleConditions(derivedRoles, rule)
				if err != nil {
					return nil, err
				}

				f := false
				for _, node := range nodes {
					if v, ok := isNodeConstBool(node); ok && v {
						f = true
						break
					}
				}

				if !f {
					switch len(nodes) {
					case 0:
						continue
					case 1:
						drNode = nodes[0]
					default:
						// combine restrictions (with OR) imposed by derived roles
						drNode = mkNodeFromLO(mkOrLogicalOperation(nodes))
					}
				}
			}

			for actionGlob := range rule.Actions {
				if !matchesActionGlob(actionGlob, input.Action) {
					continue
				}

				node, err := evaluateCondition(rule.Condition, request, rpe.Globals, variables, derivedRolesList)
				if err != nil {
					return nil, err
				}

				var filter *qpN
				if drNode == nil {
					filter = node
				} else {
					filter = mkNodeFromLO(mkAndLogicalOperation([]*qpN{drNode, node}))
				}

				result.Add(filter, rule.Effect)
			}
		}
	}

	return result, nil
}

func matchesActionGlob(actionGlob, action string) bool {
	// need to use FilterGlob here so that "*" matches anything
	return len(util.FilterGlob(actionGlob, []string{action})) > 0
}

func getDerivedRoleConditions(derivedRoles []rN, rule *runtimev1.RunnableResourcePolicySet_Policy_Rule) ([]*qpN, error) {
	var nodes []*qpN
	for _, n := range derivedRoles {
		if _, ok := rule.DerivedRoles[n.role]; ok {
			node, err := n.node()
			if err != nil {
				return nil, err
			}
			if node != nil {
				nodes = append(nodes, node)
			}
		}
	}
	return nodes, nil
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

func evaluateCondition(condition *runtimev1.Condition, request *enginev1.Request, globals map[string]any, variables map[string]*exprpb.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*enginev1.PlanResourcesAst_Node, error) {
	if condition == nil {
		return mkTrueNode(), nil
	}

	res := new(qpN)
	switch t := condition.Op.(type) {
	case *runtimev1.Condition_Any:
		nodes := make([]*qpN, 0, len(t.Any.Expr))
		for _, c := range t.Any.Expr {
			node, err := evaluateCondition(c, request, globals, variables, derivedRolesList)
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
			node, err := evaluateCondition(c, request, globals, variables, derivedRolesList)
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
			node, err := evaluateCondition(c, request, globals, variables, derivedRolesList)
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
		residual, err := evaluateConditionExpression(t.Expr.Checked, request, globals, variables, derivedRolesList)
		if err != nil {
			return nil, fmt.Errorf("error evaluating condition %q: %w", t.Expr.Original, err)
		}
		res.Node = &qpNE{Expression: residual}
	default:
		return nil, fmt.Errorf("unsupported condition type %T", t)
	}
	return res, nil
}

func evaluateConditionExpression(expr *exprpb.CheckedExpr, request *enginev1.Request, globals map[string]any, variables map[string]*exprpb.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*exprpb.CheckedExpr, error) {
	p, err := newEvaluator(request, globals)
	if err != nil {
		return nil, err
	}

	e, err := replaceVars(expr.Expr, variables)
	if err != nil {
		return nil, err
	}

	if m := request.Resource.GetAttr(); len(m) > 0 {
		e, err = replaceResourceVals(e, m)
		if err != nil {
			return nil, err
		}
	}

	e, err = replaceRuntimeEffectiveDerivedRoles(e, derivedRolesList)
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
		err = p.evalComprehensionBody(residual)
		if err != nil {
			return nil, err
		}
		m := matchers.NewExpressionProcessor()
		var r bool
		r, e, err = m.Process(residual)
		if err != nil {
			return nil, err
		}
		if !r {
			return &exprpb.CheckedExpr{Expr: residual}, nil
		}
		_, residual, err = p.evalPartially(e)
		if err != nil {
			return nil, err
		}

		return &exprpb.CheckedExpr{Expr: residual}, nil
	}

	if _, ok := val.Value().(bool); ok {
		return &exprpb.CheckedExpr{Expr: residual}, nil
	}

	return conditions.FalseExpr, nil
}

type partialEvaluator struct {
	env  *cel.Env
	vars interpreter.PartialActivation
}

func (p *partialEvaluator) evalPartially(e *exprpb.Expr) (ref.Val, *exprpb.Expr, error) {
	ast := cel.ParsedExprToAst(&exprpb.ParsedExpr{Expr: e})
	val, details, err := conditions.Eval(p.env, ast, p.vars, time.Now, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		return val, nil, err
	}

	residual := ResidualExpr(ast, details)

	return val, residual, nil
}

func newEvaluator(request *enginev1.Request, globals map[string]any) (p *partialEvaluator, err error) {
	p = new(partialEvaluator)
	knownVars := make(map[string]any)
	knownVars[conditions.CELRequestIdent] = request
	knownVars[conditions.CELPrincipalAbbrev] = request.Principal
	knownVars[conditions.CELGlobalsIdent] = globals
	knownVars[conditions.CELGlobalsAbbrev] = globals

	p.env = conditions.StdEnv
	if len(request.Resource.GetAttr()) > 0 {
		var ds []*exprpb.Decl
		for name, value := range request.Resource.Attr {
			for _, s := range conditions.ResourceAttributeNames(name) {
				ds = append(ds, decls.NewVar(s, decls.Dyn))
				knownVars[s] = value
			}
		}
		p.env, err = p.env.Extend(cel.Declarations(ds...))
		if err != nil {
			return nil, err
		}
	}
	p.vars, err = cel.PartialVars(knownVars,
		cel.AttributePattern(conditions.CELResourceAbbrev),
		cel.AttributePattern(conditions.CELRequestIdent).QualString(conditions.CELResourceField))

	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *partialEvaluator) evalComprehensionBody(e *exprpb.Expr) (err error) {
	return evalComprehensionBodyImpl(p.env, p.vars, e)
}

func evalComprehensionBodyImpl(env *cel.Env, pvars interpreter.PartialActivation, e *exprpb.Expr) (err error) {
	if e == nil {
		return nil
	}
	impl := func(e1 *exprpb.Expr) {
		if err == nil {
			err = evalComprehensionBodyImpl(env, pvars, e1)
		}
	}
	switch e := e.ExprKind.(type) {
	case *exprpb.Expr_SelectExpr:
		impl(e.SelectExpr.Operand)
	case *exprpb.Expr_CallExpr:
		impl(e.CallExpr.Target)
		for _, arg := range e.CallExpr.Args {
			impl(arg)
		}
	case *exprpb.Expr_StructExpr:
		for _, entry := range e.StructExpr.Entries {
			impl(entry.GetMapKey())
			impl(entry.GetValue())
		}
	case *exprpb.Expr_ComprehensionExpr:
		ce := e.ComprehensionExpr
		loopStep, ok := ce.LoopStep.ExprKind.(*exprpb.Expr_CallExpr)
		if !ok {
			return errors.New("expected call expr")
		}
		var i int
		if loopStep.CallExpr.Args[i].GetIdentExpr().GetName() == ce.AccuVar {
			i++
		}
		le := loopStep.CallExpr.Args[i]
		var env1 *cel.Env
		env1, err = env.Extend(cel.Declarations(decls.NewVar(ce.IterVar, decls.Dyn)))
		if err != nil {
			return err
		}
		plannerutils.UpdateIds(le)
		ast := cel.ParsedExprToAst(&exprpb.ParsedExpr{Expr: le})

		unknowns := append(pvars.UnknownAttributePatterns(), cel.AttributePattern(ce.IterVar))
		var pvars1 interpreter.PartialActivation
		pvars1, err = cel.PartialVars(pvars, unknowns...)
		if err != nil {
			return err
		}
		var det *cel.EvalDetails
		_, det, err = conditions.Eval(env1, ast, pvars1, time.Now, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
		if err != nil {
			return err
		}
		le = ResidualExpr(ast, det)
		loopStep.CallExpr.Args[i] = le
		err = evalComprehensionBodyImpl(env1, pvars1, le)
		if err != nil {
			return err
		}
		impl(ce.IterRange)
	case *exprpb.Expr_ListExpr:
		for _, element := range e.ListExpr.Elements {
			impl(element)
		}
	}

	return err
}

// ResidualExpr evaluates `residual expression` of the partial evaluation.
// There are two approaches for this:
// 1. ast := env.ResidualAst(); ast.Expr()
// 2. ResidualExpr()
// The former is the built-in approach, but unlike the latter doesn't support CEL comprehensions.
func ResidualExpr(a *cel.Ast, details *cel.EvalDetails) *exprpb.Expr {
	pruned := interpreter.PruneAst(a.Expr(), a.SourceInfo().GetMacroCalls(), details.State())
	return pruned.Expr
}

func variableExprs(variables []*runtimev1.Variable) (map[string]*exprpb.Expr, error) {
	if len(variables) == 0 {
		return nil, nil
	}

	exprs := make(map[string]*exprpb.Expr, len(variables))
	for _, variable := range variables {
		expr, err := replaceVars(variable.Expr.Checked.Expr, exprs)
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

func replaceRuntimeEffectiveDerivedRoles(expr *exprpb.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*exprpb.Expr, error) {
	return replaceVarsGen(expr, func(input *exprpb.Expr) (output *exprpb.Expr, matched bool, err error) {
		se, ok := input.ExprKind.(*exprpb.Expr_SelectExpr)
		if !ok {
			return nil, false, nil
		}

		if isRuntimeEffectiveDerivedRoles(se.SelectExpr) {
			output, err = derivedRolesList()
			return output, true, err
		}

		return nil, false, nil
	})
}

func isRuntimeEffectiveDerivedRoles(expr *exprpb.Expr_Select) bool {
	ident := expr.Operand.GetIdentExpr()

	return ident != nil &&
		ident.Name == conditions.CELRuntimeIdent &&
		(expr.Field == "effective_derived_roles" || expr.Field == "effectiveDerivedRoles")
}

func mkDerivedRolesList(derivedRoles []rN) func() (*exprpb.Expr, error) {
	return memoize(func() (_ *exprpb.Expr, err error) {
		switch len(derivedRoles) {
		case 0:
			return mkListExpr(nil), nil

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
		return plannerutils.MkCallExpr(op, args[0], args[1])
	}

	return plannerutils.MkCallExpr(op, args[0], mkBinaryOperatorExpr(op, args[1:]...))
}

func derivedRoleListElement(derivedRole rN) (*exprpb.Expr, error) {
	conditionNode, err := derivedRole.node()
	if err != nil {
		return nil, err
	}

	conditionExpr, err := qpNToExpr(conditionNode)
	if err != nil {
		return nil, err
	}

	return plannerutils.MkCallExpr(
		operators.Conditional,
		conditionExpr,
		mkListExpr([]*exprpb.Expr{mkConstStringExpr(derivedRole.role)}),
		mkListExpr(nil),
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
			return plannerutils.MkCallExpr(operators.LogicalNot, arg), nil

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

func replaceCamelCaseFields(expr *exprpb.Expr) (*exprpb.Expr, error) {
	// For some reason, the JSONFieldProvider is ignored in the planner. It _should_ work, and I haven't been able to work out why it doesn't.
	// For now, work around the issue by rewriting camel case fields to snake case.
	// We don't need to rewrite `runtime.effectiveDerivedRoles`, because that is handled in replaceRuntimeEffectiveDerivedRoles.
	return replaceVarsGen(expr, func(input *exprpb.Expr) (*exprpb.Expr, bool, error) {
		se, ok := input.ExprKind.(*exprpb.Expr_SelectExpr)
		if !ok {
			return nil, false, nil
		}
		sel := se.SelectExpr

		ident := sel.Operand.GetIdentExpr()

		if ident != nil && ident.Name == conditions.CELRequestIdent && sel.Field == "auxData" {
			return &exprpb.Expr{
				ExprKind: &exprpb.Expr_SelectExpr{
					SelectExpr: &exprpb.Expr_Select{
						Operand:  sel.Operand,
						Field:    "aux_data",
						TestOnly: sel.TestOnly,
					},
				},
			}, true, nil
		}

		return nil, false, nil
	})
}
