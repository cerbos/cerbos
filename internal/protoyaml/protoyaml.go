// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package protoyaml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unsafe"

	"github.com/bufbuild/protovalidate-go"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
)

const (
	base10    = 10
	bitSize32 = 32
	bitSize64 = 64
)

type ParseError struct {
	Err  error
	Path string
	Line int
	Col  int
}

func (pe ParseError) Error() string {
	return fmt.Sprintf("%d:%d [%s] %v", pe.Line, pe.Col, pe.Path, pe.Err)
}

func (pe ParseError) Unwrap() error {
	return pe.Err
}

type ValidationError struct {
	Msg  string
	Path string
	Line int
	Col  int
}

func (ve ValidationError) Error() string {
	return fmt.Sprintf("%d:%d [%s] %v", ve.Line, ve.Col, ve.Path, ve.Msg)
}

type unmarshalOpts struct {
	validator           *protovalidate.Validator
	fixInvalidStrings   bool
	ignoreUnknownFields bool
}

type UnmarshalOpt func(*unmarshalOpts)

// WithFixInvalidStrings makes the unmarshaler handle values that are partially quoted such as: "foo" bar.
func WithFixInvalidStrings() UnmarshalOpt {
	return func(uo *unmarshalOpts) {
		uo.fixInvalidStrings = true
	}
}

// WithIgnoreUnknownFields ignores unknown fields not defined in the protobuf schema.
func WithIgnoreUnknownFields() UnmarshalOpt {
	return func(uo *unmarshalOpts) {
		uo.ignoreUnknownFields = true
	}
}

// WithValidate validates the unmarshaled message using protovalidate.
func WithValidator(validator *protovalidate.Validator) UnmarshalOpt {
	return func(uo *unmarshalOpts) {
		uo.validator = validator
	}
}

type Unmarshaler[T proto.Message] struct {
	factory func() T
	anchors map[string]ast.Node
	unmarshalOpts
}

type unmarshalCtx struct {
	srcCtx    *sourcev1.SourceContext
	protoPath string
}

func (uc *unmarshalCtx) forField(fd protoreflect.FieldDescriptor, n ast.Node) *unmarshalCtx {
	return uc.forMapItem(string(fd.Name()), n)
}

func (uc *unmarshalCtx) forListItem(i int, n ast.Node) *unmarshalCtx {
	newPath := fmt.Sprintf("%s[%d]", uc.protoPath, i)
	uc.recordFieldPosition(newPath, n)
	return &unmarshalCtx{protoPath: newPath, srcCtx: uc.srcCtx}
}

func (uc *unmarshalCtx) forMapItem(key string, n ast.Node) *unmarshalCtx {
	var newPath string
	if uc.protoPath != "" {
		newPath = uc.protoPath + "." + key
	} else {
		newPath = key
	}

	uc.recordFieldPosition(newPath, n)
	return &unmarshalCtx{protoPath: newPath, srcCtx: uc.srcCtx}
}

func (uc *unmarshalCtx) recordFieldPosition(path string, n ast.Node) {
	if n != nil {
		if tok := n.GetToken(); tok != nil && tok.Position != nil {
			uc.srcCtx.FieldPositions[path] = &sourcev1.Position{Line: uint32(tok.Position.Line), Column: uint32(tok.Position.Column), Path: n.GetPath()}
		}
	}
}

func (uc *unmarshalCtx) errorf(n ast.Node, msg string, args ...any) error {
	err := fmt.Errorf(msg, args...)
	if n == nil {
		return uc.recordParseError(ParseError{Err: err})
	}

	tok := n.GetToken()
	if tok == nil {
		return uc.recordParseError(ParseError{Err: err, Path: n.GetPath()})
	}

	return uc.recordParseError(ParseError{
		Line: tok.Position.Line,
		Col:  tok.Position.Column,
		Path: n.GetPath(),
		Err:  err,
	})
}

func (uc *unmarshalCtx) recordParseError(pe ParseError) error {
	uc.srcCtx.Errors = append(uc.srcCtx.Errors, &sourcev1.Error{
		Kind:     sourcev1.Error_KIND_PARSE_ERROR,
		Position: &sourcev1.Position{Line: uint32(pe.Line), Column: uint32(pe.Col), Path: pe.Path},
		Message:  pe.Err.Error(),
	})

	return pe
}

func (uc *unmarshalCtx) verrorf(path, msg string) error {
	verr := ValidationError{Msg: msg, Path: path}
	if pos, ok := uc.srcCtx.FieldPositions[path]; ok {
		verr.Line = int(pos.Line)
		verr.Col = int(pos.Column)
	}

	return uc.recordValidationError(verr)
}

func (uc *unmarshalCtx) recordValidationError(ve ValidationError) error {
	uc.srcCtx.Errors = append(uc.srcCtx.Errors, &sourcev1.Error{
		Kind:     sourcev1.Error_KIND_VALIDATION_ERROR,
		Position: &sourcev1.Position{Line: uint32(ve.Line), Column: uint32(ve.Col), Path: ve.Path},
		Message:  ve.Msg,
	})

	return ve
}

func NewUnmarshaler[T proto.Message](factory func() T, opts ...UnmarshalOpt) *Unmarshaler[T] {
	uo := unmarshalOpts{}
	for _, o := range opts {
		o(&uo)
	}

	return &Unmarshaler[T]{factory: factory, unmarshalOpts: uo}
}

func (u *Unmarshaler[T]) UnmarshalReader(r io.Reader) ([]T, []*sourcev1.SourceContext, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read contents: %w", err)
	}

	return u.unmarshal(contents)
}

func (u *Unmarshaler[T]) unmarshal(contents []byte) (_ []T, _ []*sourcev1.SourceContext, outErr error) {
	t := lexer.Tokenize(unsafe.String(unsafe.SliceData(contents), len(contents)))
	if u.fixInvalidStrings {
		t = fixStringsStartingWithQuotes(t)
	}

	f, err := parser.Parse(t, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse contents: %w", err)
	}

	if len(f.Docs) == 0 {
		return nil, nil, nil
	}

	outMsg := make([]T, 0, len(f.Docs))
	outSrc := make([]*sourcev1.SourceContext, 0, len(f.Docs))
	for _, doc := range f.Docs {
		msg := u.factory()
		srcCtx := &sourcev1.SourceContext{FieldPositions: make(map[string]*sourcev1.Position)}
		uctx := &unmarshalCtx{srcCtx: srcCtx}
		if err := u.unmarshalDoc(uctx, doc, msg); err != nil {
			outErr = errors.Join(outErr, err)
		} else if err := u.validate(uctx, msg); err != nil {
			outErr = errors.Join(outErr, err)
		}

		outMsg = append(outMsg, msg)
		outSrc = append(outSrc, srcCtx)
	}

	return outMsg, outSrc, outErr
}

func fixStringsStartingWithQuotes(tokens token.Tokens) token.Tokens {
	newTokens := make(token.Tokens, 0, len(tokens))
	i := 0
	for {
		if i >= len(tokens) {
			break
		}
		tok := tokens[i]

		if tok.Prev != nil && tok.Prev.Type != token.MappingValueType {
			newTokens = append(newTokens, tok)
			i++
			continue
		}

		if !(tok.Type == token.DoubleQuoteType || tok.Type == token.SingleQuoteType) {
			newTokens = append(newTokens, tok)
			i++
			continue
		}

		if tok.Next == nil || tok.Next.Position.Line != tok.Position.Line {
			newTokens = append(newTokens, tok)
			i++
			continue
		}

		var origin strings.Builder
		var nextTok *token.Token

		origin.WriteString(tok.Origin)
		i++

		for t := tok.Next; t != nil && t.Position.Line == tok.Position.Line; t = t.Next {
			origin.WriteString(t.Origin)
			i++
			nextTok = t.Next
		}

		o := origin.String()
		v := strings.TrimSpace(o)

		var fixedTok *token.Token
		switch tok.Type {
		case token.DoubleQuoteType:
			fixedTok = token.SingleQuote(v, o, tok.Position)
		case token.SingleQuoteType:
			fixedTok = token.DoubleQuote(v, o, tok.Position)
		default:
			fixedTok = token.Folded(v, o, tok.Position)
		}
		fixedTok.Next = nextTok
		newTokens = append(newTokens, fixedTok)
	}

	return newTokens
}

func (u *Unmarshaler[T]) unmarshalDoc(uctx *unmarshalCtx, doc *ast.DocumentNode, msg T) error {
	baseNode, ok := doc.Body.(ast.MapNode)
	if !ok {
		return uctx.errorf(doc.Body, "unexpected node type %s", doc.Body.Type())
	}

	msgReflect := msg.ProtoReflect()
	return u.unmarshalMapping(uctx, baseNode, msgReflect)
}

func (u *Unmarshaler[T]) unmarshalMapping(uctx *unmarshalCtx, v ast.MapNode, out protoreflect.Message) error {
	fields := out.Descriptor().Fields()
	seen := make(map[protowire.Number]string, fields.Len())
	seenOneOfs := make(map[int]string)
	items := v.MapRange()

	for items.Next() {
		kn := items.Key()

		var keyValue string
		switch kt := kn.(type) {
		case *ast.StringNode:
			keyValue = kt.Value
		case *ast.MergeKeyNode:
			mn, err := u.resolveMerge(uctx, items.Value())
			if err != nil {
				return err
			}

			if err := u.unmarshalMapping(uctx, mn, out); err != nil {
				return err
			}

			continue
		default:
			return uctx.errorf(kn, "unexpected key type %s", kn.Type())
		}

		field := fields.ByJSONName(keyValue)
		if field == nil {
			field = fields.ByTextName(keyValue)
		}

		if field == nil {
			if u.ignoreUnknownFields {
				continue
			}
			return uctx.errorf(kn, "unknown field %s", keyValue)
		}

		if prev, ok := seen[field.Number()]; ok {
			return uctx.errorf(kn, "duplicate field definition: previous definition at %s", prev)
		}
		seen[field.Number()] = pos(kn)

		switch {
		case field.IsList():
			list := out.Mutable(field).List()
			if err := u.unmarshalList(uctx.forField(field, kn), items.Value(), field, list); err != nil {
				return err
			}
		case field.IsMap():
			mmap := out.Mutable(field).Map()
			if err := u.unmarshalMap(uctx.forField(field, kn), items.Value(), field, mmap); err != nil {
				return err
			}
		default:
			if oof := field.ContainingOneof(); oof != nil {
				idx := oof.Index()
				if prev, ok := seenOneOfs[idx]; ok {
					return uctx.errorf(kn, "invalid value: oneof field is already set at %s", prev)
				}

				seenOneOfs[idx] = pos(kn)
			}

			if err := u.unmarshalSingular(uctx.forField(field, kn), items.Value(), field, out); err != nil {
				return err
			}
		}
	}

	return nil
}

func (u *Unmarshaler[T]) resolveMerge(uctx *unmarshalCtx, n ast.Node) (ast.MapNode, error) {
	if an, ok := n.(*ast.AliasNode); ok {
		anchorName := an.Value.GetToken().Value
		aliased, ok := u.anchors[anchorName]
		if !ok {
			return nil, uctx.errorf(n, "unknown anchor %q", anchorName)
		}

		mn, ok := aliased.(ast.MapNode)
		if !ok {
			return nil, uctx.errorf(n, "expected map alias got %s", aliased.Type())
		}

		return mn, nil
	}

	return nil, uctx.errorf(n, "not an alias")
}

func (u *Unmarshaler[T]) resolveNode(uctx *unmarshalCtx, n ast.Node) (ast.Node, error) {
	switch t := n.(type) {
	case *ast.AnchorNode:
		anchorName := t.Name.GetToken().Value
		if u.anchors == nil {
			u.anchors = make(map[string]ast.Node)
			u.anchors[anchorName] = t.Value
			return t.Value, nil
		}

		if _, ok := u.anchors[anchorName]; ok {
			return nil, uctx.errorf(n, "duplicate anchor definition %q", t.String())
		}

		u.anchors[anchorName] = t.Value
		return t.Value, nil
	case *ast.AliasNode:
		anchorName := t.Value.GetToken().Value
		an, ok := u.anchors[anchorName]
		if !ok {
			return nil, uctx.errorf(n, "unknown anchor %q", anchorName)
		}

		return an, nil
	default:
		return n, nil
	}
}

func (u *Unmarshaler[T]) unmarshalList(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor, list protoreflect.List) error {
	nn, err := u.resolveNode(uctx, n)
	if err != nil {
		return err
	}

	sn, ok := nn.(*ast.SequenceNode)
	if !ok {
		return uctx.errorf(n, "expected sequence got %s", nn.Type())
	}

	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		for i, item := range sn.Values {
			val := list.NewElement()
			if err := u.unmarshalMessage(uctx.forListItem(i, item), item, val.Message()); err != nil {
				return err
			}

			list.Append(val)
		}
	default:
		for i, item := range sn.Values {
			val, err := u.unmarshalScalar(uctx.forListItem(i, item), item, fd)
			if err != nil {
				return err
			}

			list.Append(val)
		}
	}

	return nil
}

func (u *Unmarshaler[T]) unmarshalMap(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor, mmap protoreflect.Map) error {
	nn, err := u.resolveNode(uctx, n)
	if err != nil {
		return err
	}

	mn, ok := nn.(ast.MapNode)
	if !ok {
		return uctx.errorf(n, "expected map got %s", nn.Type())
	}

	var valueFn func(*unmarshalCtx, ast.Node) (protoreflect.Value, error)
	switch fd.MapValue().Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		valueFn = func(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
			val := mmap.NewValue()
			if err := u.unmarshalMessage(uctx, n, val.Message()); err != nil {
				return protoreflect.Value{}, err
			}

			return val, nil
		}
	default:
		valueFn = func(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
			return u.unmarshalScalar(uctx, n, fd.MapValue())
		}
	}

	items := mn.MapRange()
	for items.Next() {
		key, err := u.unmarshalMapKey(uctx, items.Key(), fd.MapKey())
		if err != nil {
			return err
		}

		if mmap.Has(key) {
			return uctx.errorf(items.Key(), "duplicate map key")
		}

		val, err := valueFn(uctx.forMapItem(key.String(), items.Key()), items.Value())
		if err != nil {
			return err
		}

		mmap.Set(key, val)
	}

	return nil
}

func (u *Unmarshaler[T]) unmarshalSingular(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor, out protoreflect.Message) error {
	if k := fd.Kind(); k == protoreflect.MessageKind || k == protoreflect.GroupKind {
		value := out.NewField(fd)
		if err := u.unmarshalMessage(uctx, n, value.Message()); err != nil {
			return err
		}
		out.Set(fd, value)
		return nil
	}

	value, err := u.unmarshalScalar(uctx, n, fd)
	if err != nil {
		return err
	}

	out.Set(fd, value)
	return nil
}

func (u *Unmarshaler[T]) unmarshalScalar(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	nn, err := u.resolveNode(uctx, n)
	if err != nil {
		return protoreflect.Value{}, err
	}

	switch fd.Kind() {
	case protoreflect.BoolKind:
		return u.unmarshalBool(uctx, nn)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return u.unmarshalInt(uctx, nn, bitSize32)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return u.unmarshalInt(uctx, nn, bitSize64)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return u.unmarshalUint(uctx, nn, bitSize32)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return u.unmarshalUint(uctx, nn, bitSize64)
	case protoreflect.EnumKind:
		return u.unmarshalEnum(uctx, nn, fd)
	case protoreflect.FloatKind:
		return u.unmarshalFloat(uctx, nn, bitSize32)
	case protoreflect.DoubleKind:
		return u.unmarshalFloat(uctx, nn, bitSize64)
	case protoreflect.StringKind:
		return u.unmarshalString(uctx, nn)
	case protoreflect.BytesKind:
		return u.unmarshalBytes(uctx, nn)
	default:
		return protoreflect.Value{}, uctx.errorf(n, "unknown scalar type")
	}
}

func (u *Unmarshaler[T]) unmarshalBool(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
	bn, ok := n.(*ast.BoolNode)
	if !ok {
		return protoreflect.Value{}, uctx.errorf(n, "expected boolean value got %s", n.Type())
	}

	return protoreflect.ValueOfBool(bn.Value), nil
}

func (u *Unmarshaler[T]) unmarshalEnum(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	switch t := n.(type) {
	case *ast.StringNode:
		if ev := fd.Enum().Values().ByName(protoreflect.Name(t.Value)); ev != nil {
			return protoreflect.ValueOfEnum(ev.Number()), nil
		}
		return protoreflect.Value{}, uctx.errorf(n, "invalid enum value %q", t.Value)
	case *ast.IntegerNode:
		switch tv := t.Value.(type) {
		case uint64:
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(tv)), nil
		case int64:
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(tv)), nil
		default:
			return protoreflect.Value{}, uctx.errorf(n, "invalid enum value %q", t.Value)
		}
	case *ast.NullNode:
		return protoreflect.ValueOfEnum(0), nil
	default:
		return protoreflect.Value{}, uctx.errorf(n, "invalid enum value")
	}
}

func (u *Unmarshaler[T]) unmarshalString(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
	switch t := n.(type) {
	case *ast.StringNode:
		return protoreflect.ValueOfString(t.Value), nil
	case *ast.LiteralNode:
		return protoreflect.ValueOfString(t.Value.Value), nil
	case *ast.NullNode:
		return protoreflect.ValueOf(""), nil
	case *ast.IntegerNode:
		switch tv := t.Value.(type) {
		case uint64:
			return protoreflect.ValueOfString(strconv.FormatUint(tv, 10)), nil
		case int64:
			return protoreflect.ValueOfString(strconv.FormatInt(tv, 10)), nil
		default:
			return protoreflect.Value{}, uctx.errorf(n, "unexpected integer value %q", t.Value)
		}
	default:
		return protoreflect.Value{}, uctx.errorf(n, "expected string value got %s", n.Type())
	}
}

//nolint:dupl
func (u *Unmarshaler[T]) unmarshalInt(uctx *unmarshalCtx, n ast.Node, bitSize int) (protoreflect.Value, error) {
	switch t := n.(type) {
	case *ast.IntegerNode:
		switch tv := t.Value.(type) {
		case uint64:
			if bitSize == bitSize32 {
				return protoreflect.ValueOfInt32(int32(tv)), nil
			}
			return protoreflect.ValueOfInt64(int64(tv)), nil
		case int64:
			if bitSize == bitSize32 {
				return protoreflect.ValueOfInt32(int32(tv)), nil
			}
			return protoreflect.ValueOfInt64(tv), nil
		default:
			return protoreflect.Value{}, uctx.errorf(n, "invalid integer value %q", t.Value)
		}
	case *ast.StringNode:
		s := strings.TrimSpace(t.Value)
		v, err := strconv.ParseInt(s, base10, bitSize)
		if err != nil {
			return protoreflect.Value{}, uctx.errorf(n, "invalid integer value %q: %w", v, err)
		}
		if bitSize == bitSize32 {
			return protoreflect.ValueOfInt32(int32(v)), nil
		}
		return protoreflect.ValueOfInt64(v), nil
	default:
		return protoreflect.Value{}, uctx.errorf(n, "expected integer value got %s", n.Type())
	}
}

//nolint:dupl
func (u *Unmarshaler[T]) unmarshalUint(uctx *unmarshalCtx, n ast.Node, bitSize int) (protoreflect.Value, error) {
	switch t := n.(type) {
	case *ast.IntegerNode:
		switch tv := t.Value.(type) {
		case uint64:
			if bitSize == bitSize32 {
				return protoreflect.ValueOfUint32(uint32(tv)), nil
			}
			return protoreflect.ValueOfUint64(tv), nil
		case int64:
			if bitSize == bitSize32 {
				return protoreflect.ValueOfUint32(uint32(tv)), nil
			}
			return protoreflect.ValueOfUint64(uint64(tv)), nil
		default:
			return protoreflect.Value{}, uctx.errorf(n, "invalid integer value %q", t.Value)
		}
	case *ast.StringNode:
		s := strings.TrimSpace(t.Value)
		v, err := strconv.ParseUint(s, base10, bitSize)
		if err != nil {
			return protoreflect.Value{}, uctx.errorf(n, "invalid integer value %q: %w", v, err)
		}
		if bitSize == bitSize32 {
			return protoreflect.ValueOfUint32(uint32(v)), nil
		}
		return protoreflect.ValueOfUint64(v), nil
	default:
		return protoreflect.Value{}, uctx.errorf(n, "expected integer value got %s", n.Type())
	}
}

func (u *Unmarshaler[T]) unmarshalFloat(uctx *unmarshalCtx, n ast.Node, bitSize int) (protoreflect.Value, error) {
	switch t := n.(type) {
	case *ast.IntegerNode:
		switch tv := t.Value.(type) {
		case uint64:
			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(tv)), nil
			}
			return protoreflect.ValueOfFloat64(float64(tv)), nil
		case int64:
			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(tv)), nil
			}
			return protoreflect.ValueOfFloat64(float64(tv)), nil
		default:
			return protoreflect.Value{}, uctx.errorf(n, "invalid float value %q", t.Value)
		}
	case *ast.FloatNode:
		if bitSize == bitSize32 {
			return protoreflect.ValueOfFloat32(float32(t.Value)), nil
		}
		return protoreflect.ValueOfFloat64(t.Value), nil
	case *ast.StringNode:
		switch t.Value {
		case "NaN":
			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(math.NaN())), nil
			}
			return protoreflect.ValueOfFloat64(math.NaN()), nil
		case "Infinity":
			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(math.Inf(+1))), nil
			}
			return protoreflect.ValueOfFloat64(math.Inf(+1)), nil
		case "-Infinity":
			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(math.Inf(-1))), nil
			}
			return protoreflect.ValueOfFloat64(math.Inf(-1)), nil
		default:
			s := strings.TrimSpace(t.Value)
			v, err := strconv.ParseFloat(s, bitSize)
			if err != nil {
				return protoreflect.Value{}, uctx.errorf(n, "invalid float value %q: %w", s, err)
			}

			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(v)), nil
			}
			return protoreflect.ValueOfFloat64(v), nil
		}
	default:
		return protoreflect.Value{}, uctx.errorf(n, "expected float value got %s", n.Type())
	}
}

func (u *Unmarshaler[T]) unmarshalBytes(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
	var s string
	switch t := n.(type) {
	case *ast.StringNode:
		s = t.Value
	case *ast.LiteralNode:
		s = t.Value.Value
	default:
		return protoreflect.Value{}, uctx.errorf(n, "expected string value got %s", n.Type())
	}

	enc := base64.StdEncoding
	if strings.ContainsAny(s, "-_") {
		enc = base64.URLEncoding
	}

	if len(s)%4 != 0 {
		enc = enc.WithPadding(base64.NoPadding)
	}

	b, err := enc.DecodeString(s)
	if err != nil {
		return protoreflect.Value{}, uctx.errorf(n, "failed to decode bytes: %w", err)
	}

	return protoreflect.ValueOfBytes(b), nil
}

func (u *Unmarshaler[T]) unmarshalMessage(uctx *unmarshalCtx, n ast.Node, out protoreflect.Message) error {
	nn, err := u.resolveNode(uctx, n)
	if err != nil {
		return err
	}

	mn, ok := nn.(ast.MapNode)
	if !ok {
		return uctx.errorf(n, "expected object got %s", nn.Type())
	}

	return u.unmarshalMapping(uctx, mn, out)
}

func (u *Unmarshaler[T]) unmarshalMapKey(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.MapKey, error) {
	sn, ok := n.(*ast.StringNode)
	if !ok {
		return protoreflect.MapKey{}, uctx.errorf(n, "expected string got %s", n.Type())
	}

	switch fd.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(sn.Value).MapKey(), nil
	case protoreflect.BoolKind:
		switch sn.Value {
		case "true":
			return protoreflect.ValueOfBool(true).MapKey(), nil
		case "false":
			return protoreflect.ValueOfBool(false).MapKey(), nil
		default:
			return protoreflect.MapKey{}, uctx.errorf(n, "invalid boolean value %q", sn.Value)
		}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		v, err := strconv.ParseInt(sn.Value, 10, 32)
		if err != nil {
			return protoreflect.MapKey{}, uctx.errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfInt32(int32(v)).MapKey(), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		v, err := strconv.ParseInt(sn.Value, 10, 64)
		if err != nil {
			return protoreflect.MapKey{}, uctx.errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfInt64(v).MapKey(), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		v, err := strconv.ParseUint(sn.Value, 10, 32)
		if err != nil {
			return protoreflect.MapKey{}, uctx.errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfUint32(uint32(v)).MapKey(), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		v, err := strconv.ParseUint(sn.Value, 10, 64)
		if err != nil {
			return protoreflect.MapKey{}, uctx.errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfUint64(v).MapKey(), nil
	default:
		return protoreflect.MapKey{}, uctx.errorf(n, "unsupported map key type %s", fd.Kind())
	}
}

func (u *Unmarshaler[T]) validate(uctx *unmarshalCtx, msg T) (outErr error) {
	if u.validator == nil {
		return nil
	}

	err := u.validator.Validate(msg)
	if err == nil {
		return nil
	}

	verrs := new(protovalidate.ValidationError)
	if !errors.As(err, &verrs) {
		return err
	}

	for _, v := range verrs.Violations {
		path := v.GetFieldPath()
		outErr = errors.Join(outErr, uctx.verrorf(path, v.GetMessage()))
	}

	return outErr
}

func pos(n ast.Node) string {
	if n == nil {
		return ""
	}

	tok := n.GetToken()
	if tok == nil {
		return ""
	}

	return fmt.Sprintf("[%d:%d]", tok.Position.Line, tok.Position.Column)
}
