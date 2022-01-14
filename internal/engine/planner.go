// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
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
)

type (
	qpN   = enginev1.ResourcesQueryPlanOutput_Node
	qpNLO = enginev1.ResourcesQueryPlanOutput_Node_LogicalOperation
	qpNE  = enginev1.ResourcesQueryPlanOutput_Node_Expression
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

func (ppe *principalPolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.ResourcesQueryPlanRequest) (*enginev1.ResourcesQueryPlanOutput, error) {
	_, span := tracing.StartSpan(ctx, "principal_policy.EvaluateResourcesQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(ppe.policy.Meta.Fqn))
	defer span.End()

	inputActions := []string{input.Action}
	result := &enginev1.ResourcesQueryPlanOutput{}
	result.RequestId = input.RequestId
	result.Kind = input.Resource.Kind
	result.Action = input.Action

	nodeBoolTrue := &qpN{Node: &qpNE{Expression: conditions.TrueExpr}}
	for _, p := range ppe.policy.Policies { // zero or one policy in the set
		for resource, resourceRules := range p.ResourceRules {
			if !globs.matches(resource, input.Resource.Kind) {
				continue
			}

			for actionGlob, rule := range resourceRules.ActionRules {
				matchedActions := globMatch(actionGlob, inputActions)
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
					result.Filter = node
				}

				if result.Filter == nil {
					result.Filter = nodeBoolTrue // No restrictions on this resource
				}

				if rule.Effect == effectv1.Effect_EFFECT_DENY {
					result.Filter = invertNodeBooleanValue(result.Filter)
				}

				return result, nil
			}
		}
	}

	if result.Filter == nil {
		result.Filter = nodeBoolTrue // No restrictions on this resource
	}
	return result, nil
}

func (rpe *resourcePolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.ResourcesQueryPlanRequest) (*enginev1.ResourcesQueryPlanOutput, error) {
	_, span := tracing.StartSpan(ctx, "resource_policy.EvaluateResourcesQueryPlan")
	span.SetAttributes(tracing.PolicyFQN(rpe.policy.Meta.Fqn))
	defer span.End()

	effectiveRoles := toSet(input.Principal.Roles)
	inputActions := []string{input.Action}
	result := &enginev1.ResourcesQueryPlanOutput{}
	result.RequestId = input.RequestId
	result.Kind = input.Resource.Kind
	result.Action = input.Action
	var allowFilter, denyFilter []*qpN

	for _, p := range rpe.policy.Policies { // zero or one policy in the set
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
				matchedActions := globMatch(actionGlob, inputActions)
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
					result.Filter = node
				} else {
					result.Filter = drNode

					if node != nil {
						// node AND drNode
						result.Filter = mkNodeFromLO(mkAndLogicalOperation([]*qpN{drNode, node}))
					}
				}

				if rule.Effect == effectv1.Effect_EFFECT_DENY {
					denyFilter = append(denyFilter, invertNodeBooleanValue(result.Filter))
				} else if rule.Effect == effectv1.Effect_EFFECT_ALLOW {
					allowFilter = append(allowFilter, result.Filter)
				}
			}
		}
	}

	switch a, d := len(allowFilter), len(denyFilter); a {
	case 0:
		switch d {
		case 0:
			result.Filter = &qpN{Node: &qpNE{Expression: conditions.TrueExpr}} // default value sets no restrictions on this resource
		case 1:
			result.Filter = denyFilter[0]
		default:
			result.Filter = mkNodeFromLO(mkAndLogicalOperation(denyFilter))
		}
	case 1:
		if d == 0 {
			result.Filter = allowFilter[0]
		} else {
			nodes := make([]*qpN, d+1)
			copy(nodes, denyFilter)
			nodes[len(nodes)-1] = allowFilter[0]
			result.Filter = mkNodeFromLO(mkAndLogicalOperation(nodes))
		}
	default:
		switch d {
		case 0:
			result.Filter = mkNodeFromLO(mkOrLogicalOperation(allowFilter))
		default:
			nodes := make([]*qpN, d+1)
			copy(nodes, denyFilter)
			nodes[len(nodes)-1] = mkNodeFromLO(mkOrLogicalOperation(allowFilter))
			result.Filter = mkNodeFromLO(mkAndLogicalOperation(nodes))
		}
	}

	return result, nil
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

func isNodeConstBool(node *enginev1.ResourcesQueryPlanOutput_Node) (bool, bool) {
	if e, ok := node.Node.(*enginev1.ResourcesQueryPlanOutput_Node_Expression); ok {
		if e1 := e.Expression.GetExpr().GetConstExpr(); e1 != nil {
			if b, ok := e1.ConstantKind.(*exprpb.Constant_BoolValue); ok {
				return b.BoolValue, true
			}
		}
	}

	return false, false
}

func mkNodeFromLO(lo *enginev1.ResourcesQueryPlanOutput_LogicalOperation) *enginev1.ResourcesQueryPlanOutput_Node {
	// node AND drNode
	return &qpN{Node: &qpNLO{LogicalOperation: lo}}
}

func mkOrLogicalOperation(nodes []*enginev1.ResourcesQueryPlanOutput_Node) *enginev1.ResourcesQueryPlanOutput_LogicalOperation {
	return &enginev1.ResourcesQueryPlanOutput_LogicalOperation{
		Operator: enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_OR,
		Nodes:    nodes,
	}
}

func mkAndLogicalOperation(nodes []*enginev1.ResourcesQueryPlanOutput_Node) *enginev1.ResourcesQueryPlanOutput_LogicalOperation {
	return &enginev1.ResourcesQueryPlanOutput_LogicalOperation{
		Operator: enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_AND,
		Nodes:    nodes,
	}
}

func invertNodeBooleanValue(node *enginev1.ResourcesQueryPlanOutput_Node) *enginev1.ResourcesQueryPlanOutput_Node {
	lo := &enginev1.ResourcesQueryPlanOutput_LogicalOperation{
		Operator: enginev1.ResourcesQueryPlanOutput_LogicalOperation_OPERATOR_NOT,
		Nodes:    []*enginev1.ResourcesQueryPlanOutput_Node{node},
	}
	return &qpN{Node: &qpNLO{LogicalOperation: lo}}
}

func evaluateCondition(condition *runtimev1.Condition, input *enginev1.ResourcesQueryPlanRequest, variables map[string]*exprpb.Expr) (*enginev1.ResourcesQueryPlanOutput_Node, error) {
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

func evaluateCELExprPartially(expr *exprpb.CheckedExpr, input *enginev1.ResourcesQueryPlanRequest, variables map[string]*exprpb.Expr) (*bool, *exprpb.CheckedExpr, error) {
	e := expr.Expr
	e, err := replaceVars(e, variables)
	if err != nil {
		return nil, nil, err
	}
	ast := cel.ParsedExprToAst(&exprpb.ParsedExpr{Expr: e})
	knownVars := make(map[string]interface{})
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
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		return nil, nil, err
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

	val, details, err := prg.Eval(vars)
	if err != nil {
		if strings.HasPrefix(err.Error(), "no such key:") {
			return nil, nil, &NoSuchKeyError{msg: fmt.Sprintf("missing principal attribute %q", strings.TrimPrefix(err.Error(), "no such key: "))}
		}
		return nil, nil, err
	}
	residual, err := env.ResidualAst(ast, details)
	if err != nil {
		return nil, nil, err
	}
	ast, iss := env.Check(residual)
	if iss != nil {
		return nil, nil, fmt.Errorf("failed to check residual express: %w", iss.Err())
	}
	checkedExpr, err := cel.AstToCheckedExpr(ast)
	if err != nil {
		return nil, nil, err
	}
	if types.IsUnknown(val) {
		return nil, checkedExpr, nil
	}
	if b, ok := val.Value().(bool); ok {
		return &b, checkedExpr, nil
	}
	return nil, checkedExpr, fmt.Errorf("unexpected result type %T", val.Value())
}
