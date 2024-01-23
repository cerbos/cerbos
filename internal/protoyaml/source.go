// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package protoyaml

import (
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/printer"

	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
)

type SourceCtx struct {
	doc *ast.DocumentNode
	*sourcev1.SourceContext
}

func newSourceCtx(srcCtx *sourcev1.SourceContext, doc *ast.DocumentNode) SourceCtx {
	return SourceCtx{doc: doc, SourceContext: srcCtx}
}

func (sc SourceCtx) StartPosition() *sourcev1.Position {
	if sp := sc.GetStartPosition(); sp != nil {
		return &sourcev1.Position{
			Line:   sp.GetLine(),
			Column: sp.GetColumn(),
		}
	}

	return nil
}

func (sc SourceCtx) PositionForPath(path string) *sourcev1.Position {
	return sc.GetFieldPositions()[path]
}

func (sc SourceCtx) ContextForPath(path string) string {
	if path == "" {
		return ""
	}

	yamlPath, err := yaml.PathString(path)
	if err != nil {
		return ""
	}

	node, err := yamlPath.FilterNode(sc.doc)
	if err != nil {
		return ""
	}

	var errPrinter printer.Printer
	return errPrinter.PrintErrorToken(node.GetToken(), false)
}
