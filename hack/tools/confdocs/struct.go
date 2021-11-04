package confdocs

import (
	"go/ast"
	"go/token"
	"go/types"
)

type Struct struct {
	FilePos    token.Pos
	StructName string
	RawStruct  *ast.StructType
	Fields     []*StructField
	Methods    []*StructMethod
}

func (s *Struct) doesImplementInterface(iface *types.Interface) {

}

type StructMethod struct {
	FilePos         token.Pos
	ReceiverType    string
	FunctionName    string
	RawFunctionDecl *ast.FuncDecl
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
