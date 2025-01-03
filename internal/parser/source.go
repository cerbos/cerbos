// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package parser

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

func NewEmptySourceCtx() SourceCtx {
	return SourceCtx{}
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

func (sc SourceCtx) PositionForProtoPath(path string) *sourcev1.Position {
	return sc.GetFieldPositions()[path]
}

func (sc SourceCtx) ContextForYAMLPath(path string) string {
	if sc.doc == nil || path == "" {
		return ""
	}

	yamlPath, err := yaml.PathString(path)
	if err != nil {
		return ""
	}

	node, err := yamlPath.FilterNode(sc.doc.Body)
	if err != nil {
		return ""
	}

	var errPrinter printer.Printer
	return errPrinter.PrintErrorToken(node.GetToken(), false)
}

func (sc SourceCtx) PositionAndContextForProtoPath(path string) (pos *sourcev1.Position, context string) {
	pos = sc.PositionForProtoPath(path)
	if pos != nil {
		context = sc.ContextForYAMLPath(pos.GetPath())
	}

	return pos, context
}
