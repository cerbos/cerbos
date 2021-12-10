// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

type (
	qpN   = enginev1.ResourcesQueryPlanOutput_Node
	qpNLO = enginev1.ResourcesQueryPlanOutput_Node_LogicalOperation
	qpNE  = enginev1.ResourcesQueryPlanOutput_Node_Expression
	rN    = struct {
		role string
		f    func() (*qpN, error)
		node *qpN
	}
)

func (rpe *resourcePolicyEvaluator) EvaluateResourcesQueryPlan(_ context.Context, input *requestv1.ResourcesQueryPlanRequest) (*enginev1.ResourcesQueryPlanOutput, error) {
	effectiveRoles := toSet(input.Principal.Roles)
	inputActions := []string{input.Action}
	result := &enginev1.ResourcesQueryPlanOutput{}
	result.RequestId = input.RequestId
	result.Kind = input.ResourceKind
	result.Action = input.Action

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

		// evaluate each rule until all actions have a result
		for _, rule := range p.Rules {
			var drNode *qpN
			if !setIntersects(rule.Roles, effectiveRoles) {
				nodes, err := getDerivedRoleConditions(derivedRoles, rule)
				if err != nil {
					return nil, err
				}
				switch len(nodes) {
				case 0:
					continue
				case 1:
					drNode = nodes[0]
				default:
					// combine restrictions (with OR) imposed by derived roles
					drNode = &qpN{Node: &qpNLO{LogicalOperation: mkOrLogicalOperation(nodes)}}
				}
			}
			if rule.Effect == effectv1.Effect_EFFECT_DENY {
				panic("rules with effect DENY not supported")
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
					// node AND drNode
					if node != nil {
						result.Filter = &qpN{Node: &qpNLO{LogicalOperation: mkAndLogicalOperation([]*qpN{drNode, node})}}
					} else {
						result.Filter = drNode
					}
				}
			}
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
			nodes = append(nodes, node)
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

func evaluateCondition(condition *runtimev1.Condition, input *requestv1.ResourcesQueryPlanRequest, variables map[string]*exprpb.Expr) (*enginev1.ResourcesQueryPlanOutput_Node, error) {
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
		res.Node = &qpNLO{
			LogicalOperation: mkOrLogicalOperation(nodes),
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
		res.Node = &qpNLO{LogicalOperation: mkAndLogicalOperation(nodes)}
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

func evaluateCELExprPartially(expr *exprpb.CheckedExpr, input *requestv1.ResourcesQueryPlanRequest, variables map[string]*exprpb.Expr) (*bool, *exprpb.CheckedExpr, error) {
	e := expr.Expr
	err := replaceVars(&e, variables)
	if err != nil {
		return nil, nil, err
	}
	ast := cel.ParsedExprToAst(&exprpb.ParsedExpr{Expr: e})
	env := conditions.StdPartialEnv
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		return nil, nil, err
	}

	vars, err := cel.PartialVars(map[string]interface{}{
		conditions.CELRequestIdent:                   input,
		conditions.CELPrincipalAbbrev:                input.Principal,
		conditions.Fqn(conditions.CELPrincipalField): input.Principal,
	},
		cel.AttributePattern(conditions.CELResourceAbbrev),
		cel.AttributePattern(conditions.CELRequestIdent).QualString(conditions.CELResourceField))
	if err != nil {
		return nil, nil, err
	}

	val, details, err := prg.Eval(vars)
	if err != nil {
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
