// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"github.com/google/cel-go/common/ast"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

func attributeAndVariableVisitor(
	setAttr func(name string, t responsev1.InspectPoliciesResponse_Attribute_Type),
	setVar func(name, value string),
) ast.Visitor {
	return ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.SelectKind {
			return
		}

		selectNode := e.AsSelect()
		operandNode := selectNode.Operand()
		switch operandNode.Kind() {
		case ast.IdentKind:
			if setVar == nil {
				return
			}

			ident := operandNode.AsIdent()
			if ident == conditions.CELVariablesIdent || ident == conditions.CELVariablesAbbrev {
				setVar(selectNode.FieldName(), selectNode.FieldName())
			}
		case ast.SelectKind:
			if setAttr == nil {
				return
			}

			ident := operandNode.AsSelect()
			if ident.FieldName() == conditions.CELAttrField {
				attrName := selectNode.FieldName()
				switch ident.Operand().Kind() {
				case ast.SelectKind:
					root := ident.Operand().AsSelect()
					if root.FieldName() == conditions.CELPrincipalField || root.FieldName() == conditions.CELPrincipalAbbrev {
						setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_TYPE_PRINCIPAL_ATTRIBUTE)
					} else if root.FieldName() == conditions.CELResourceField || root.FieldName() == conditions.CELResourceAbbrev {
						setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE)
					}
				case ast.IdentKind:
					root := ident.Operand().AsIdent()
					if root == conditions.CELPrincipalField || root == conditions.CELPrincipalAbbrev {
						setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_TYPE_PRINCIPAL_ATTRIBUTE)
					} else if root == conditions.CELResourceField || root == conditions.CELResourceAbbrev {
						setAttr(attrName, responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE)
					}
				default:
				}
			}
		default:
		}
	})
}
