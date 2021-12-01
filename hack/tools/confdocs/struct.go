package confdocs

import (
	"go/ast"
	"go/token"
	"go/types"
)

const unnamedField = "<UNKNOWN_FIELD>"

type Struct struct {
	FilePos token.Pos
	Fields  []*StructField
	Methods []*StructMethod
	Raw     *ast.StructType
	Typed   *types.Struct
	PkgPath string
	Name    string
}

type StructMethod struct {
	FilePos      token.Pos
	ReceiverType string
	Name         string
	ReturnType   string
	Raw          *ast.FuncDecl
}

type StructField struct {
	Name   string
	Docs   string
	Tags   string
	Fields []*StructField
}

func NewStructFieldFromIdentArray(nameField []*ast.Ident, docsField *ast.CommentGroup, tagsField *ast.BasicLit, fields []*StructField) *StructField {
	var docs = ""
	var tags = ""
	var name = unnamedField

	if tagsField != nil {
		tags = tagsField.Value
	}

	if docsField != nil && docsField.List != nil && docsField.List[0] != nil {
		docs = docsField.List[0].Text
	}

	if nameField != nil && nameField[0] != nil {
		name = nameField[0].Name
	}

	return &StructField{
		Name:   name,
		Docs:   docs,
		Tags:   tags,
		Fields: fields,
	}
}

func NewStructField(nameField *ast.Ident, docsField *ast.CommentGroup, tagsField *ast.BasicLit, fields []*StructField) *StructField {
	var docs = ""
	var tags = ""
	var name = unnamedField

	if tagsField != nil {
		tags = tagsField.Value
	}

	if docsField != nil && docsField.List != nil && docsField.List[0] != nil {
		docs = docsField.List[0].Text
	}

	if nameField != nil {
		name = nameField.Name
	}

	return &StructField{
		Name:   name,
		Docs:   docs,
		Tags:   tags,
		Fields: fields,
	}
}
