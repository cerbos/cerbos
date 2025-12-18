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

func (sc SourceCtx) PositionOfMapKeyAtProtoPath(path string) *sourcev1.Position {
	return sc.GetMapKeyPositions()[path]
}

func (sc SourceCtx) PositionOfValueAtProtoPath(path string) *sourcev1.Position {
	return sc.GetFieldPositions()[path]
}

func (sc SourceCtx) ContextForMapKeyAtYAMLPath(path string) string {
	valueNode := sc.nodeAtYAMLPath(path)
	if valueNode == nil {
		return ""
	}

	mappingValueNode, ok := ast.Parent(sc.doc.Body, valueNode).(*ast.MappingValueNode)
	if !ok {
		return ""
	}

	return sc.contextForNode(mappingValueNode.Key)
}

func (sc SourceCtx) ContextForValueAtYAMLPath(path string) string {
	return sc.contextForNode(sc.nodeAtYAMLPath(path))
}

func (sc SourceCtx) nodeAtYAMLPath(path string) ast.Node {
	if sc.doc == nil || path == "" {
		return nil
	}

	yamlPath, err := yaml.PathString(path)
	if err != nil {
		return nil
	}

	node, err := yamlPath.FilterNode(sc.doc.Body)
	if err != nil {
		return nil
	}

	return node
}

func (sc SourceCtx) contextForNode(node ast.Node) string {
	if node == nil {
		return ""
	}

	var errPrinter printer.Printer
	return errPrinter.PrintErrorToken(node.GetToken(), false)
}

func (sc SourceCtx) PositionAndContextForMapKeyAtProtoPath(path string) (pos *sourcev1.Position, context string) {
	pos = sc.PositionOfMapKeyAtProtoPath(path)
	if pos != nil {
		context = sc.ContextForMapKeyAtYAMLPath(pos.GetPath())
	}

	return pos, context
}

func (sc SourceCtx) PositionAndContextForValueAtProtoPath(path string) (pos *sourcev1.Position, context string) {
	pos = sc.PositionOfValueAtProtoPath(path)
	if pos != nil {
		context = sc.ContextForValueAtYAMLPath(pos.GetPath())
	}

	return pos, context
}
