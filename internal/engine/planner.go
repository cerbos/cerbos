// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/cel-go/interpreter"
)

type (
	qpN   = enginev1.PlanResourcesAst_Node
	qpNLO = enginev1.PlanResourcesAst_Node_LogicalOperation
	qpNE  = enginev1.PlanResourcesAst_Node_Expression
	rN    = struct {
		f    func() (*qpN, error)
		node *qpN
		role string
	}
	NoSuchKeyError struct {
		msg string
	}
)

func (e *NoSuchKeyError) Error() string {
	return e.msg
}

func (ppe *principalPolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.PlanResourcesInput) (*enginev1.PlanResourcesOutput, error) {
	_, span := tracing.StartSpan(ctx, "principal_policy.EvaluateResourcesQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(ppe.policy.Meta.Fqn))
	defer span.End()

	inputActions := []string{input.Action}
	var filterAST *enginev1.PlanResourcesAst_Node
	var scope string

	nodeBoolTrue := mkTrueNode()
	for _, p := range ppe.policy.Policies { // zero or one policy in the set
		scope = p.Scope
		for resource, resourceRules := range p.ResourceRules {
			if !util.MatchesGlob(resource, input.Resource.Kind) {
				continue
			}

			for actionGlob, rule := range resourceRules.ActionRules {
				matchedActions := util.FilterGlob(actionGlob, inputActions)
				if len(matchedActions) == 0 {
					continue
				}
				variables := make(map[string]*exprpb.Expr, len(p.Variables))
				for k, v := range p.Variables {
					variables[k] = v.Checked.Expr
				}

				if rule.Condition != nil {
					node, err := evaluateCondition(rule.Condition, input, variables)
					if err != nil {
						return nil, err
					}
					filterAST = node
				}

				if filterAST == nil {
					filterAST = nodeBoolTrue // No restrictions on this resource
				}

				if rule.Effect == effectv1.Effect_EFFECT_DENY {
					filterAST = invertNodeBooleanValue(filterAST)
				}

				return mkPlanResourcesOutput(input, scope, filterAST)
			}
		}
	}

	return mkPlanResourcesOutput(input, scope, mkFalseNode())
}

func mkPlanResourcesOutput(input *enginev1.PlanResourcesInput, scope string, filterAST *enginev1.PlanResourcesAst_Node) (*enginev1.PlanResourcesOutput, error) {
	result := &enginev1.PlanResourcesOutput{
		RequestId:     input.RequestId,
		Kind:          input.Resource.Kind,
		PolicyVersion: input.Resource.PolicyVersion,
		Action:        input.Action,
		Scope:         scope,
	}

	var err error
	result.Filter, err = toFilter(filterAST)
	if err != nil {
		return nil, err
	}

	if input.IncludeMeta {
		result.FilterDebug = filterToString(result.Filter)
	}

	return result, nil
}

func (rpe *resourcePolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.PlanResourcesInput) (*enginev1.PlanResourcesOutput, error) {
	_, span := tracing.StartSpan(ctx, "resource_policy.EvaluateResourcesQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(rpe.policy.Meta.Fqn))
	defer span.End()

	effectiveRoles := toSet(input.Principal.Roles)
	inputActions := []string{input.Action}
	var allowFilter, denyFilter []*qpN
	var filterAST *enginev1.PlanResourcesAst_Node
	var scope string

	for _, p := range rpe.policy.Policies { // there might be more than 1 policy if there are scoped policies
		// if previous iteration has found a matching policy, then quit the loop
		if len(allowFilter) > 0 || len(denyFilter) > 0 {
			break
		}
		scope = p.Scope

		var derivedRoles []rN

		for drName, dr := range p.DerivedRoles {
			dr := dr
			if !setIntersects(dr.ParentRoles, effectiveRoles) {
				continue
			}

			derivedRoles = append(derivedRoles, rN{
				role: drName,
				f: func() (*qpN, error) {
					if dr.Condition == nil {
						return nil, nil
					}
					drVariables := make(map[string]*exprpb.Expr, len(dr.Variables))
					for k, v := range dr.Variables {
						drVariables[k] = v.Checked.Expr
					}
					node, err := evaluateCondition(dr.Condition, input, drVariables)
					if err != nil {
						return nil, err
					}
					return node, nil
				},
				node: nil,
			})
		}

		for _, rule := range p.Rules {
			var drNode *qpN
			if !setIntersects(rule.Roles, effectiveRoles) {
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
				matchedActions := util.FilterGlob(actionGlob, inputActions)
				if len(matchedActions) == 0 {
					continue
				}
				variables := make(map[string]*exprpb.Expr, len(p.Variables))
				for k, v := range p.Variables {
					variables[k] = v.Checked.Expr
				}
				var node *qpN
				var err error
				if rule.Condition != nil {
					node, err = evaluateCondition(rule.Condition, input, variables)
					if err != nil {
						return nil, err
					}
				}

				if drNode == nil {
					filterAST = node
				} else {
					filterAST = drNode

					if node != nil {
						// node AND drNode
						filterAST = mkNodeFromLO(mkAndLogicalOperation([]*qpN{drNode, node}))
					}
				}

				//nolint:exhaustive
				switch rule.Effect {
				case effectv1.Effect_EFFECT_DENY:
					denyFilter = append(denyFilter, invertNodeBooleanValue(filterAST))
				case effectv1.Effect_EFFECT_ALLOW:
					allowFilter = append(allowFilter, filterAST)
				}
			}
		}
	}

	switch a, d := len(allowFilter), len(denyFilter); a {
	case 0:
		switch d {
		case 0:
			filterAST = mkFalseNode() // default to DENY
		case 1:
			filterAST = denyFilter[0]
		default:
			filterAST = mkNodeFromLO(mkAndLogicalOperation(denyFilter))
		}
	case 1:
		if d == 0 {
			filterAST = allowFilter[0]
		} else {
			nodes := make([]*qpN, d+1)
			copy(nodes, denyFilter)
			nodes[len(nodes)-1] = allowFilter[0]
			filterAST = mkNodeFromLO(mkAndLogicalOperation(nodes))
		}
	default:
		switch d {
		case 0:
			filterAST = mkNodeFromLO(mkOrLogicalOperation(allowFilter))
		default:
			nodes := make([]*qpN, d+1)
			copy(nodes, denyFilter)
			nodes[len(nodes)-1] = mkNodeFromLO(mkOrLogicalOperation(allowFilter))
			filterAST = mkNodeFromLO(mkAndLogicalOperation(nodes))
		}
	}

	return mkPlanResourcesOutput(input, scope, filterAST)
}

func getDerivedRoleConditions(derivedRoles []rN, rule *runtimev1.RunnableResourcePolicySet_Policy_Rule) ([]*qpN, error) {
	var nodes []*qpN
	for _, n := range derivedRoles {
		if _, ok := rule.DerivedRoles[n.role]; ok {
			node := n.node
			var err error
			if node == nil {
				node, err = n.f()
				if err != nil {
					return nil, err
				}
				n.node = node
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

func evaluateCondition(condition *runtimev1.Condition, input *enginev1.PlanResourcesInput, variables map[string]*exprpb.Expr) (*enginev1.PlanResourcesAst_Node, error) {
	res := new(qpN)
	switch t := condition.Op.(type) {
	case *runtimev1.Condition_Any:
		nodes := make([]*qpN, 0, len(t.Any.Expr))
		for _, c := range t.Any.Expr {
			node, err := evaluateCondition(c, input, variables)
			if err != nil {
				return nil, err
			}

			add := true

			if b, ok := isNodeConstBool(node); ok {
				if b {
					res.Node = &qpNE{Expression: conditions.TrueExpr}
					return res, nil
				}
				add = false
			}

			if add {
				nodes = append(nodes, node)
			}
		}
		switch len(nodes) {
		case 0:
			res.Node = &qpNE{Expression: conditions.TrueExpr}
		case 1:
			res.Node = nodes[0].Node
		default:
			res.Node = &qpNLO{LogicalOperation: mkOrLogicalOperation(nodes)}
		}
	case *runtimev1.Condition_All:
		nodes := make([]*qpN, 0, len(t.All.Expr))
		for _, c := range t.All.Expr {
			node, err := evaluateCondition(c, input, variables)
			if err != nil {
				return nil, err
			}
			add := true

			if b, ok := isNodeConstBool(node); ok {
				if !b {
					res.Node = &qpNE{Expression: conditions.FalseExpr}
					return res, nil
				}
				add = false
			}

			if add {
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
			node, err := evaluateCondition(c, input, variables)
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
		_, residual, err := evaluateCELExprPartially(t.Expr.Checked, input, variables)
		if err != nil {
			return nil, fmt.Errorf("error evaluating condition %q: %w", t.Expr.Original, err)
		}
		res.Node = &qpNE{Expression: residual}
	default:
		return nil, fmt.Errorf("unsupported condition type %T", t)
	}
	return res, nil
}

func evaluateCELExprPartially(expr *exprpb.CheckedExpr, input *enginev1.PlanResourcesInput, variables map[string]*exprpb.Expr) (*bool, *exprpb.CheckedExpr, error) {
	e := expr.Expr
	e, err := replaceVars(e, variables)
	if err != nil {
		return nil, nil, err
	}
	ast := cel.ParsedExprToAst(&exprpb.ParsedExpr{Expr: e})
	knownVars := make(map[string]any)
	env := conditions.StdPartialEnv
	if len(input.Resource.GetAttr()) > 0 {
		var ds []*exprpb.Decl
		for name, value := range input.Resource.Attr {
			for _, s := range conditions.ResourceAttributeNames(name) {
				ds = append(ds, decls.NewVar(s, decls.Dyn))
				knownVars[s] = value
			}
		}
		env, err = env.Extend(cel.Declarations(ds...))
		if err != nil {
			return nil, nil, err
		}
	}

	knownVars[conditions.CELRequestIdent] = input
	knownVars[conditions.CELPrincipalAbbrev] = input.Principal
	knownVars[conditions.Fqn(conditions.CELPrincipalField)] = input.Principal

	vars, err := cel.PartialVars(knownVars,
		cel.AttributePattern(conditions.CELResourceAbbrev),
		cel.AttributePattern(conditions.CELRequestIdent).QualString(conditions.CELResourceField))
	if err != nil {
		return nil, nil, err
	}

	val, details, err := conditions.Eval(env, ast, vars, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		if strings.HasPrefix(err.Error(), "no such key:") {
			return nil, nil, &NoSuchKeyError{msg: fmt.Sprintf("missing principal attribute %q", strings.TrimPrefix(err.Error(), "no such key: "))}
		}
		return nil, nil, err
	}
	residual := ResidualExpr(ast, details)
	if types.IsUnknown(val) {
		err = evalComprehensionBody(env, vars, residual)
		if err != nil {
			return nil, nil, err
		}
		checkedExpr := &exprpb.CheckedExpr{Expr: residual}

		return nil, checkedExpr, nil
	}
	checkedExpr := &exprpb.CheckedExpr{Expr: residual}
	if b, ok := val.Value().(bool); ok {
		return &b, checkedExpr, nil
	}
	return nil, checkedExpr, fmt.Errorf("unexpected result type %T", val.Value())
}

func evalComprehensionBody(env *cel.Env, pvars interpreter.PartialActivation, e *exprpb.Expr) (err error) {
	if e == nil {
		return nil
	}
	impl := func(e1 *exprpb.Expr) {
		if err == nil {
			err = evalComprehensionBody(env, pvars, e1)
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
		env1, err := env.Extend(cel.Declarations(decls.NewVar(ce.IterVar, decls.Dyn)))
		if err != nil {
			return err
		}
		updateIds(le)
		ast := cel.ParsedExprToAst(&exprpb.ParsedExpr{Expr: le})
		partialVars, err := cel.PartialVars(pvars, cel.AttributePattern(ce.IterVar))
		if err != nil {
			return err
		}
		_, det, err := conditions.Eval(env1, ast, partialVars, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
		if err != nil {
			return err
		}
		le = ResidualExpr(ast, det)
		loopStep.CallExpr.Args[i] = le
		err = evalComprehensionBody(env1, partialVars, le)
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
	pruned := interpreter.PruneAst(a.Expr(), details.State())
	return pruned
}
