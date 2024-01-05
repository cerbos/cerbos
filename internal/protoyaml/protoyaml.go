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

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
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

type unmarshalOpts struct {
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

type Unmarshaler[T proto.Message] struct {
	factory func() T
	anchors map[string]ast.Node
	unmarshalOpts
}

func NewUnmarshaler[T proto.Message](factory func() T, opts ...UnmarshalOpt) *Unmarshaler[T] {
	uo := unmarshalOpts{}
	for _, o := range opts {
		o(&uo)
	}

	return &Unmarshaler[T]{factory: factory, unmarshalOpts: uo}
}

func (u *Unmarshaler[T]) UnmarshalReader(r io.Reader) ([]T, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read contents: %w", err)
	}

	return u.unmarshal(contents)
}

func (u *Unmarshaler[T]) unmarshal(contents []byte) (_ []T, outErr error) {
	t := lexer.Tokenize(unsafe.String(unsafe.SliceData(contents), len(contents)))
	if u.fixInvalidStrings {
		t = fixStringsStartingWithQuotes(t)
	}

	f, err := parser.Parse(t, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse contents: %w", err)
	}

	if len(f.Docs) == 0 {
		return nil, nil
	}

	out := make([]T, 0, len(f.Docs))
	for _, doc := range f.Docs {
		t, err := u.unmarshalDoc(doc)
		if err != nil {
			outErr = errors.Join(outErr, err)
			continue
		}

		out = append(out, t)
	}

	return out, outErr
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

func (u *Unmarshaler[T]) unmarshalDoc(doc *ast.DocumentNode) (T, error) {
	obj := u.factory()
	outReflect := obj.ProtoReflect()

	baseNode, ok := doc.Body.(ast.MapNode)
	if !ok {
		return obj, errorf(doc.Body, "unexpected node type %s", doc.Body.Type())
	}

	err := u.unmarshalMapping(baseNode, outReflect)
	return obj, err
}

func (u *Unmarshaler[T]) unmarshalMapping(v ast.MapNode, out protoreflect.Message) error {
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
			mn, err := u.resolveMerge(items.Value())
			if err != nil {
				return err
			}

			if err := u.unmarshalMapping(mn, out); err != nil {
				return err
			}

			continue
		default:
			return errorf(kn, "unexpected key type %s", kn.Type())
		}

		field := fields.ByJSONName(keyValue)
		if field == nil {
			field = fields.ByTextName(keyValue)
		}

		if field == nil {
			if u.ignoreUnknownFields {
				continue
			}
			return errorf(kn, "unknown field %s", keyValue)
		}

		if prev, ok := seen[field.Number()]; ok {
			return errorf(kn, "duplicate field definition: previous definition at %s", prev)
		}
		seen[field.Number()] = pos(kn)

		switch {
		case field.IsList():
			list := out.Mutable(field).List()
			if err := u.unmarshalList(items.Value(), field, list); err != nil {
				return err
			}
		case field.IsMap():
			mmap := out.Mutable(field).Map()
			if err := u.unmarshalMap(items.Value(), field, mmap); err != nil {
				return err
			}
		default:
			if oof := field.ContainingOneof(); oof != nil {
				idx := oof.Index()
				if prev, ok := seenOneOfs[idx]; ok {
					return errorf(kn, "invalid value: oneof field is already set at %s", prev)
				}

				seenOneOfs[idx] = pos(kn)
			}

			if err := u.unmarshalSingular(items.Value(), field, out); err != nil {
				return err
			}
		}
	}

	return nil
}

func (u *Unmarshaler[T]) resolveMerge(n ast.Node) (ast.MapNode, error) {
	if an, ok := n.(*ast.AliasNode); ok {
		anchorName := an.Value.GetToken().Value
		aliased, ok := u.anchors[anchorName]
		if !ok {
			return nil, errorf(n, "unknown anchor %q", anchorName)
		}

		mn, ok := aliased.(ast.MapNode)
		if !ok {
			return nil, errorf(n, "expected map alias got %s", aliased.Type())
		}

		return mn, nil
	}

	return nil, errorf(n, "not an alias")
}

func (u *Unmarshaler[T]) resolveNode(n ast.Node) (ast.Node, error) {
	switch t := n.(type) {
	case *ast.AnchorNode:
		anchorName := t.Name.GetToken().Value
		if u.anchors == nil {
			u.anchors = make(map[string]ast.Node)
			u.anchors[anchorName] = t.Value
			return t.Value, nil
		}

		if _, ok := u.anchors[anchorName]; ok {
			return nil, errorf(n, "duplicate anchor definition %q", t.String())
		}

		u.anchors[anchorName] = t.Value
		return t.Value, nil
	case *ast.AliasNode:
		anchorName := t.Value.GetToken().Value
		an, ok := u.anchors[anchorName]
		if !ok {
			return nil, errorf(n, "unknown anchor %q", anchorName)
		}

		return an, nil
	default:
		return n, nil
	}
}

func (u *Unmarshaler[T]) unmarshalList(n ast.Node, fd protoreflect.FieldDescriptor, list protoreflect.List) error {
	nn, err := u.resolveNode(n)
	if err != nil {
		return err
	}

	sn, ok := nn.(*ast.SequenceNode)
	if !ok {
		return errorf(n, "expected sequence got %s", nn.Type())
	}

	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		for _, item := range sn.Values {
			val := list.NewElement()
			if err := u.unmarshalMessage(item, val.Message()); err != nil {
				return err
			}

			list.Append(val)
		}
	default:
		for _, item := range sn.Values {
			val, err := u.unmarshalScalar(item, fd)
			if err != nil {
				return err
			}

			list.Append(val)
		}
	}

	return nil
}

func (u *Unmarshaler[T]) unmarshalMap(n ast.Node, fd protoreflect.FieldDescriptor, mmap protoreflect.Map) error {
	nn, err := u.resolveNode(n)
	if err != nil {
		return err
	}

	mn, ok := nn.(ast.MapNode)
	if !ok {
		return errorf(n, "expected map got %s", nn.Type())
	}

	var valueFn func(ast.Node) (protoreflect.Value, error)
	switch fd.MapValue().Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		valueFn = func(n ast.Node) (protoreflect.Value, error) {
			val := mmap.NewValue()
			if err := u.unmarshalMessage(n, val.Message()); err != nil {
				return protoreflect.Value{}, err
			}

			return val, nil
		}
	default:
		valueFn = func(n ast.Node) (protoreflect.Value, error) {
			return u.unmarshalScalar(n, fd.MapValue())
		}
	}

	items := mn.MapRange()
	for items.Next() {
		key, err := u.unmarshalMapKey(items.Key(), fd.MapKey())
		if err != nil {
			return err
		}

		if mmap.Has(key) {
			return errorf(items.Key(), "duplicate map key")
		}

		val, err := valueFn(items.Value())
		if err != nil {
			return err
		}

		mmap.Set(key, val)
	}

	return nil
}

func (u *Unmarshaler[T]) unmarshalSingular(n ast.Node, fd protoreflect.FieldDescriptor, out protoreflect.Message) error {
	if k := fd.Kind(); k == protoreflect.MessageKind || k == protoreflect.GroupKind {
		value := out.NewField(fd)
		if err := u.unmarshalMessage(n, value.Message()); err != nil {
			return err
		}
		out.Set(fd, value)
		return nil
	}

	value, err := u.unmarshalScalar(n, fd)
	if err != nil {
		return err
	}

	out.Set(fd, value)
	return nil
}

func (u *Unmarshaler[T]) unmarshalScalar(n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	nn, err := u.resolveNode(n)
	if err != nil {
		return protoreflect.Value{}, err
	}

	switch fd.Kind() {
	case protoreflect.BoolKind:
		return u.unmarshalBool(nn)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return u.unmarshalInt(nn, bitSize32)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return u.unmarshalInt(nn, bitSize64)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return u.unmarshalUint(nn, bitSize32)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return u.unmarshalUint(nn, bitSize64)
	case protoreflect.EnumKind:
		return u.unmarshalEnum(nn, fd)
	case protoreflect.FloatKind:
		return u.unmarshalFloat(nn, bitSize32)
	case protoreflect.DoubleKind:
		return u.unmarshalFloat(nn, bitSize64)
	case protoreflect.StringKind:
		return u.unmarshalString(nn)
	case protoreflect.BytesKind:
		return u.unmarshalBytes(nn)
	default:
		return protoreflect.Value{}, errorf(n, "unknown scalar type")
	}
}

func (u *Unmarshaler[T]) unmarshalBool(n ast.Node) (protoreflect.Value, error) {
	bn, ok := n.(*ast.BoolNode)
	if !ok {
		return protoreflect.Value{}, errorf(n, "expected boolean value got %s", n.Type())
	}

	return protoreflect.ValueOfBool(bn.Value), nil
}

func (u *Unmarshaler[T]) unmarshalEnum(n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	switch t := n.(type) {
	case *ast.StringNode:
		if ev := fd.Enum().Values().ByName(protoreflect.Name(t.Value)); ev != nil {
			return protoreflect.ValueOfEnum(ev.Number()), nil
		}
		return protoreflect.Value{}, errorf(n, "invalid enum value %q", t.Value)
	case *ast.IntegerNode:
		switch tv := t.Value.(type) {
		case uint64:
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(tv)), nil
		case int64:
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(tv)), nil
		default:
			return protoreflect.Value{}, errorf(n, "invalid enum value %q", t.Value)
		}
	case *ast.NullNode:
		return protoreflect.ValueOfEnum(0), nil
	default:
		return protoreflect.Value{}, errorf(n, "invalid enum value")
	}
}

func (u *Unmarshaler[T]) unmarshalString(n ast.Node) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, errorf(n, "unexpected integer value %q", t.Value)
		}
	default:
		return protoreflect.Value{}, errorf(n, "expected string value got %s", n.Type())
	}
}

//nolint:dupl
func (u *Unmarshaler[T]) unmarshalInt(n ast.Node, bitSize int) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, errorf(n, "invalid integer value %q", t.Value)
		}
	case *ast.StringNode:
		s := strings.TrimSpace(t.Value)
		v, err := strconv.ParseInt(s, base10, bitSize)
		if err != nil {
			return protoreflect.Value{}, errorf(n, "invalid integer value %q: %w", v, err)
		}
		if bitSize == bitSize32 {
			return protoreflect.ValueOfInt32(int32(v)), nil
		}
		return protoreflect.ValueOfInt64(v), nil
	default:
		return protoreflect.Value{}, errorf(n, "expected integer value got %s", n.Type())
	}
}

//nolint:dupl
func (u *Unmarshaler[T]) unmarshalUint(n ast.Node, bitSize int) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, errorf(n, "invalid integer value %q", t.Value)
		}
	case *ast.StringNode:
		s := strings.TrimSpace(t.Value)
		v, err := strconv.ParseUint(s, base10, bitSize)
		if err != nil {
			return protoreflect.Value{}, errorf(n, "invalid integer value %q: %w", v, err)
		}
		if bitSize == bitSize32 {
			return protoreflect.ValueOfUint32(uint32(v)), nil
		}
		return protoreflect.ValueOfUint64(v), nil
	default:
		return protoreflect.Value{}, errorf(n, "expected integer value got %s", n.Type())
	}
}

func (u *Unmarshaler[T]) unmarshalFloat(n ast.Node, bitSize int) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, errorf(n, "invalid float value %q", t.Value)
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
				return protoreflect.Value{}, errorf(n, "invalid float value %q: %w", s, err)
			}

			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(v)), nil
			}
			return protoreflect.ValueOfFloat64(v), nil
		}
	default:
		return protoreflect.Value{}, errorf(n, "expected float value got %s", n.Type())
	}
}

func (u *Unmarshaler[T]) unmarshalBytes(n ast.Node) (protoreflect.Value, error) {
	var s string
	switch t := n.(type) {
	case *ast.StringNode:
		s = t.Value
	case *ast.LiteralNode:
		s = t.Value.Value
	default:
		return protoreflect.Value{}, errorf(n, "expected string value got %s", n.Type())
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
		return protoreflect.Value{}, errorf(n, "failed to decode bytes: %w", err)
	}

	return protoreflect.ValueOfBytes(b), nil
}

func (u *Unmarshaler[T]) unmarshalMessage(n ast.Node, out protoreflect.Message) error {
	nn, err := u.resolveNode(n)
	if err != nil {
		return err
	}

	mn, ok := nn.(ast.MapNode)
	if !ok {
		return errorf(n, "expected object got %s", nn.Type())
	}

	return u.unmarshalMapping(mn, out)
}

func (u *Unmarshaler[T]) unmarshalMapKey(n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.MapKey, error) {
	sn, ok := n.(*ast.StringNode)
	if !ok {
		return protoreflect.MapKey{}, errorf(n, "expected string got %s", n.Type())
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
			return protoreflect.MapKey{}, errorf(n, "invalid boolean value %q", sn.Value)
		}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		v, err := strconv.ParseInt(sn.Value, 10, 32)
		if err != nil {
			return protoreflect.MapKey{}, errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfInt32(int32(v)).MapKey(), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		v, err := strconv.ParseInt(sn.Value, 10, 64)
		if err != nil {
			return protoreflect.MapKey{}, errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfInt64(v).MapKey(), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		v, err := strconv.ParseUint(sn.Value, 10, 32)
		if err != nil {
			return protoreflect.MapKey{}, errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfUint32(uint32(v)).MapKey(), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		v, err := strconv.ParseUint(sn.Value, 10, 64)
		if err != nil {
			return protoreflect.MapKey{}, errorf(n, "invalid integer value %q: %w", sn.Value, err)
		}
		return protoreflect.ValueOfUint64(v).MapKey(), nil
	default:
		return protoreflect.MapKey{}, errorf(n, "unsupported map key type %s", fd.Kind())
	}
}

func errorf(n ast.Node, msg string, args ...any) error {
	err := fmt.Errorf(msg, args...)
	if n == nil {
		return err
	}

	tok := n.GetToken()
	if tok == nil {
		return ParseError{Err: err, Path: n.GetPath()}
	}

	return ParseError{
		Line: tok.Position.Line,
		Col:  tok.Position.Column,
		Path: n.GetPath(),
		Err:  fmt.Errorf(msg, args...),
	}
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
