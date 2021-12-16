package indexer

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

const unknownField = "<UNKNOWN_FIELD>"

type Struct struct {
	FilePos token.Pos
	Fields  []*StructField
	Raw     *ast.StructType
	Typed   *types.Struct
	PkgPath string
	Name    string
	Docs    string
}

type StructField struct {
	Name     string
	Docs     string
	Tags     string
	TagsData *TagsData
	Fields   []*StructField
}

func NewStructFieldFromIdentArray(nameField []*ast.Ident, docsField *ast.CommentGroup, tagsField *ast.BasicLit, fields []*StructField) (*StructField, error) {
	var err error
	var docs = ""
	var tags = ""
	var name = unknownField
	var tagsData *TagsData

	if tagsField != nil {
		tags = tagsField.Value[1 : len(tagsField.Value)-1]
		tagsData, err = ParseTags(tags)
		if err != nil && !errors.As(err, &errTagNotExists) {
			return nil, fmt.Errorf("failed to parse tags: %w", err)
		}
	}

	if docsField != nil && docsField.List != nil && docsField.List[0] != nil {
		docs = strings.TrimSpace(strings.TrimPrefix(docsField.List[0].Text, "//"))
	}

	if nameField != nil && nameField[0] != nil {
		name = nameField[0].Name
	}

	return &StructField{
		Name:     name,
		Docs:     docs,
		Tags:     tags,
		TagsData: tagsData,
		Fields:   fields,
	}, nil
}

func NewStructField(nameField *ast.Ident, docsField *ast.CommentGroup, tagsField *ast.BasicLit, fields []*StructField) (*StructField, error) {
	var err error
	var docs = ""
	var tags = ""
	var name = unknownField
	var tagsData *TagsData

	if tagsField != nil {
		tags = tagsField.Value[1 : len(tagsField.Value)-1]
		tagsData, err = ParseTags(tags)
		if err != nil && !errors.As(err, &errTagNotExists) {
			return nil, fmt.Errorf("failed to parse tags: %w", err)
		}
	}

	if docsField != nil && docsField.List != nil && docsField.List[0] != nil {
		docs = strings.TrimSpace(strings.TrimPrefix(docsField.List[0].Text, "//"))
	}

	if nameField != nil {
		name = nameField.Name
	}

	return &StructField{
		Name:     name,
		Docs:     docs,
		Tags:     tags,
		TagsData: tagsData,
		Fields:   fields,
	}, nil
}
