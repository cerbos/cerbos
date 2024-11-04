// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/google/cel-go/common/ast"
)

func visitCompiledPolicySet(policySet *runtimev1.RunnablePolicySet, visitor ast.Visitor) error {
	switch ps := policySet.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, policy := range ps.PrincipalPolicy.Policies {
			for _, variable := range policy.OrderedVariables {
				if err := visitCompiledExpr(variable.Expr, visitor); err != nil {
					return fmt.Errorf("failed in the compiled principal policy variable %q: %w", variable.Name, err)
				}
			}

			for _, rule := range policy.ResourceRules {
				for _, actionRule := range rule.ActionRules {
					if err := visitCompiledCondition(actionRule.Condition, visitor); err != nil {
						return fmt.Errorf("failed in the compiled principal policy rule: %w", err)
					}
				}
			}
		}

		return nil

	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		for _, policy := range ps.ResourcePolicy.Policies {
			for _, variable := range policy.OrderedVariables {
				if err := visitCompiledExpr(variable.Expr, visitor); err != nil {
					return fmt.Errorf("failed in the compiled resource policy variable %q: %w", variable.Name, err)
				}
			}

			for _, dr := range policy.DerivedRoles {
				for _, variable := range dr.OrderedVariables {
					if err := visitCompiledExpr(variable.Expr, visitor); err != nil {
						return fmt.Errorf("failed in the compiled derived role variable %q: %w", variable.Name, err)
					}
				}

				if err := visitCompiledCondition(dr.Condition, visitor); err != nil {
					return fmt.Errorf("failed in the compiled derived roles definition: %w", err)
				}
			}

			for _, rule := range policy.Rules {
				if err := visitCompiledCondition(rule.Condition, visitor); err != nil {
					return fmt.Errorf("failed in the compiled resource policy rule: %w", err)
				}
			}
		}

		return nil

	case *runtimev1.RunnablePolicySet_DerivedRoles, *runtimev1.RunnablePolicySet_Variables, *runtimev1.RunnablePolicySet_RolePolicy:
		return nil

	default:
		return fmt.Errorf("unexpected policy set type %T", policySet)
	}
}

func visitPolicy(policy *policyv1.Policy, visitor ast.Visitor) error {
	err := visitVariables(policy.Variables, visitor) //nolint:staticcheck
	if err != nil {
		return fmt.Errorf("failed in top-level policy variables: %w", err)
	}

	switch pt := policy.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		if err := visitVariables(pt.DerivedRoles.GetVariables().GetLocal(), visitor); err != nil {
			return fmt.Errorf("failed in derived role local variables: %w", err)
		}

		for _, def := range pt.DerivedRoles.Definitions {
			if err := visitCondition(def.Condition, visitor); err != nil {
				return fmt.Errorf("failed in derived role definition %q: %w", def.Name, err)
			}
		}

		return nil

	case *policyv1.Policy_ExportVariables:
		if err := visitVariables(pt.ExportVariables.Definitions, visitor); err != nil {
			return fmt.Errorf("failed in export variables definitions: %w", err)
		}

		return nil

	case *policyv1.Policy_PrincipalPolicy:
		if err := visitVariables(pt.PrincipalPolicy.GetVariables().GetLocal(), visitor); err != nil {
			return fmt.Errorf("failed in principal policy local variables: %w", err)
		}

		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if err := visitCondition(action.Condition, visitor); err != nil {
					return fmt.Errorf("failed in principal policy rule: %w", err)
				}
			}
		}

		return nil

	case *policyv1.Policy_ResourcePolicy:
		if err := visitVariables(pt.ResourcePolicy.GetVariables().GetLocal(), visitor); err != nil {
			return fmt.Errorf("failed in resource policy local variables: %w", err)
		}

		for _, rule := range pt.ResourcePolicy.Rules {
			if err := visitCondition(rule.Condition, visitor); err != nil {
				return fmt.Errorf("failed in resource policy rule: %w", err)
			}
		}

		return nil

	case *policyv1.Policy_ExportConstants, *policyv1.Policy_RolePolicy:
		return nil

	default:
		return fmt.Errorf("unexpected policy type %T", policy)
	}
}

func visitVariables(variables map[string]string, visitor ast.Visitor) error {
	for name, expr := range variables {
		if err := visitExpr(expr, visitor); err != nil {
			return fmt.Errorf("failed in variable %q: %w", name, err)
		}
	}

	return nil
}

func visitExpr(expr string, visitor ast.Visitor) error {
	condition := &policyv1.Condition{
		Condition: &policyv1.Condition_Match{
			Match: &policyv1.Match{
				Op: &policyv1.Match_Expr{
					Expr: expr,
				},
			},
		},
	}

	if err := visitCondition(condition, visitor); err != nil {
		return fmt.Errorf("failed in expression: %w", err)
	}

	return nil
}

func visitCondition(condition *policyv1.Condition, visitor ast.Visitor) error {
	if condition == nil {
		return nil
	}

	compiled, err := compile.Condition(condition)
	if err != nil {
		return fmt.Errorf("failed to compile condition: %w", err)
	}

	if err := visitCompiledCondition(compiled, visitor); err != nil {
		return fmt.Errorf("failed in compiled condition: %w", err)
	}

	return nil
}

func visitCompiledCondition(condition *runtimev1.Condition, visitor ast.Visitor) error {
	if condition == nil {
		return nil
	}

	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		return visitCompiledConditionExprList(op.All, visitor)
	case *runtimev1.Condition_Any:
		return visitCompiledConditionExprList(op.Any, visitor)
	case *runtimev1.Condition_Expr:
		return visitCompiledExpr(op.Expr, visitor)
	case *runtimev1.Condition_None:
		return visitCompiledConditionExprList(op.None, visitor)
	default:
		return fmt.Errorf("unexpected condition type %T", condition.Op)
	}
}

func visitCompiledConditionExprList(exprList *runtimev1.Condition_ExprList, visitor ast.Visitor) error {
	for _, condition := range exprList.Expr {
		if err := visitCompiledCondition(condition, visitor); err != nil {
			return fmt.Errorf("failed in compiled condition expression list: %w", err)
		}
	}

	return nil
}

func visitCompiledExpr(expr *runtimev1.Expr, visitor ast.Visitor) error {
	exprAST, err := ast.ToAST(expr.Checked)
	if err != nil {
		return fmt.Errorf("failed to convert checked expression %q to AST: %w", expr.Original, err)
	}

	ast.PreOrderVisit(exprAST.Expr(), visitor)
	return nil
}
