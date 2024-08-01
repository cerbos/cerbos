// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"

	"github.com/google/cel-go/common/ast"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

func attributeVisitor(
	setAttr func(name string, k responsev1.InspectPoliciesResponse_Attribute_Kind),
) ast.Visitor {
	return ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.SelectKind {
			return
		}
		selectNode := e.AsSelect()
		operandNode := selectNode.Operand()
		if operandNode.Kind() != ast.SelectKind {
			return
		}

		ident := operandNode.AsSelect()
		if ident.FieldName() == conditions.CELAttrField {
			attrName := selectNode.FieldName()
			switch ident.Operand().Kind() {
			case ast.SelectKind:
				root := ident.Operand().AsSelect()
				if root.FieldName() == conditions.CELPrincipalField || root.FieldName() == conditions.CELPrincipalAbbrev {
					setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_KIND_PRINCIPAL_ATTRIBUTE)
				} else if root.FieldName() == conditions.CELResourceField || root.FieldName() == conditions.CELResourceAbbrev {
					setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_KIND_RESOURCE_ATTRIBUTE)
				}
			case ast.IdentKind:
				root := ident.Operand().AsIdent()
				if root == conditions.CELPrincipalField || root == conditions.CELPrincipalAbbrev {
					setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_KIND_PRINCIPAL_ATTRIBUTE)
				} else if root == conditions.CELResourceField || root == conditions.CELResourceAbbrev {
					setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_KIND_RESOURCE_ATTRIBUTE)
				}
			default:
			}
		}
	})
}

func referencedAttributesInCompiledCondition(condition *runtimev1.Condition, out map[string]*responsev1.InspectPoliciesResponse_Attribute) error {
	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		for _, condition := range op.All.Expr {
			if err := referencedAttributesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced attributes in the 'all' expression: %w", err)
			}
		}
	case *runtimev1.Condition_Any:
		for _, condition := range op.Any.Expr {
			if err := referencedAttributesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced attributes in the 'any' expression: %w", err)
			}
		}
	case *runtimev1.Condition_Expr:
		exprAST, err := ast.ToAST(op.Expr.Checked)
		if err != nil {
			return fmt.Errorf("failed to convert checked expression %s to AST: %w", op.Expr.Checked, err)
		}

		ast.PreOrderVisit(
			exprAST.Expr(),
			attributeVisitor(
				func(name string, k responsev1.InspectPoliciesResponse_Attribute_Kind) {
					switch k {
					case responsev1.InspectPoliciesResponse_Attribute_KIND_PRINCIPAL_ATTRIBUTE:
						out[fmt.Sprintf("%s|%s", conditions.CELPrincipalAbbrev, name)] = &responsev1.InspectPoliciesResponse_Attribute{
							Name: name,
							Kind: k,
						}
					case responsev1.InspectPoliciesResponse_Attribute_KIND_RESOURCE_ATTRIBUTE:
						out[fmt.Sprintf("%s|%s", conditions.CELResourceAbbrev, name)] = &responsev1.InspectPoliciesResponse_Attribute{
							Name: name,
							Kind: k,
						}
					default:
					}
				},
			),
		)
	case *runtimev1.Condition_None:
		for _, condition := range op.None.Expr {
			if err := referencedAttributesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced attributes in the 'none' expression: %w", err)
			}
		}
	}

	return nil
}
