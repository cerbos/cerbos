// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"github.com/google/cel-go/common/ast"

	"github.com/cerbos/cerbos/internal/conditions"
)

func variableVisitor(
	setVar func(name, value string),
) ast.Visitor {
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
			setVar(selectNode.FieldName(), selectNode.FieldName())
		}
	})
}
