// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"

	"github.com/google/cel-go/common/ast"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

func attributeVisitor(attrs map[string]*responsev1.InspectPoliciesResponse_Attribute) ast.Visitor {
	setAttr := func(root, name string) {
		switch root {
		case conditions.CELPrincipalField, conditions.CELPrincipalAbbrev:
			attrs[fmt.Sprintf("%s|%s", conditions.CELPrincipalAbbrev, name)] = &responsev1.InspectPoliciesResponse_Attribute{
				Name: name,
				Kind: responsev1.InspectPoliciesResponse_Attribute_KIND_PRINCIPAL_ATTRIBUTE,
			}

		case conditions.CELResourceField, conditions.CELResourceAbbrev:
			attrs[fmt.Sprintf("%s|%s", conditions.CELResourceAbbrev, name)] = &responsev1.InspectPoliciesResponse_Attribute{
				Name: name,
				Kind: responsev1.InspectPoliciesResponse_Attribute_KIND_RESOURCE_ATTRIBUTE,
			}
		}
	}

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
				setAttr(ident.Operand().AsSelect().FieldName(), attrName)
			case ast.IdentKind:
				setAttr(ident.Operand().AsIdent(), attrName)
			default:
			}
		}
	})
}

func constantVisitor(consts map[string]*responsev1.InspectPoliciesResponse_Constant) ast.Visitor {
	return ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.SelectKind {
			return
		}

		selectNode := e.AsSelect()
		operandNode := selectNode.Operand()
		if operandNode.Kind() != ast.IdentKind {
			return
		}

		ident := operandNode.AsIdent()
		if ident == conditions.CELConstantsIdent || ident == conditions.CELConstantsAbbrev {
			consts[selectNode.FieldName()] = &responsev1.InspectPoliciesResponse_Constant{
				Name: selectNode.FieldName(),
				Kind: responsev1.InspectPoliciesResponse_Constant_KIND_UNKNOWN,
				Used: true,
			}
		}
	})
}

func variableVisitor(vars map[string]*responsev1.InspectPoliciesResponse_Variable) ast.Visitor {
	return ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.SelectKind {
			return
		}

		selectNode := e.AsSelect()
		operandNode := selectNode.Operand()
		if operandNode.Kind() != ast.IdentKind {
			return
		}

		ident := operandNode.AsIdent()
		if ident == conditions.CELVariablesIdent || ident == conditions.CELVariablesAbbrev {
			vars[selectNode.FieldName()] = &responsev1.InspectPoliciesResponse_Variable{
				Name: selectNode.FieldName(),
				Kind: responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN,
				Used: true,
			}
		}
	})
}
