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
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
	"github.com/goccy/go-yaml/token"
	"github.com/stoewer/go-strcase"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	base10    = 10
	bitSize32 = 32
	bitSize64 = 64
)

var ErrNotFound = errors.New("not found")

// Find a single document from the multi-document stream.
// TODO(cell): Optimize!
// For our use case, this could be optimized by storing the offset of each document and directly seeking to that offset.
// However, there are a couple of problems with that:
//  1. The offsets reported by the parser are not always reliable (I am yet to figure out why)
//  2. If YAML anchors have been used, we need to resolve those first by reading through the entire file anyway
//     However, this is a relatively niche case and we can handle that case lazily (seek first, read, and resolve anchors only if they exist in the doc)
//
// In the interest of time, I am leaving those optimizations for later.
func Find[T proto.Message](r io.Reader, match func(T) bool, out T, opts ...UnmarshalOpt) error {
	contents, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read contents: %w", err)
	}

	f, err := parse(contents, false)
	if err != nil {
		return err
	}

	if len(f.Docs) == 0 {
		return ErrNotFound
	}

	u := &unmarshaler[T]{unmarshalOpts: unmarshalOpts{}}
	for _, o := range opts {
		o(&u.unmarshalOpts)
	}

	for _, doc := range f.Docs {
		bodyNode, ok := doc.Body.(ast.MapNode)
		if !ok {
			// Ignore documents not structured as policies
			continue
		}

		proto.Reset(out)
		refOut := out.ProtoReflect()
		uctx := newUnmarshalCtxWithoutSourceCtx(doc)

		if err := u.unmarshalMapping(uctx, bodyNode, refOut); err != nil {
			continue
		}

		if !match(out) {
			continue
		}

		return u.validate(uctx, out)
	}

	return ErrNotFound
}

func Unmarshal[T proto.Message](r io.Reader, factory func() T, opts ...UnmarshalOpt) ([]T, []SourceCtx, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read contents: %w", err)
	}

	return UnmarshalBytes(contents, factory, opts...)
}

func UnmarshalBytes[T proto.Message](contents []byte, factory func() T, opts ...UnmarshalOpt) (_ []T, _ []SourceCtx, outErr error) {
	f, err := parse(contents, true)
	if err != nil {
		return nil, nil, err
	}

	if len(f.Docs) == 0 {
		return nil, nil, nil
	}

	u := &unmarshaler[T]{unmarshalOpts: unmarshalOpts{}}
	for _, o := range opts {
		o(&u.unmarshalOpts)
	}

	outMsg := make([]T, 0, len(f.Docs))
	outSrc := make([]SourceCtx, 0, len(f.Docs))
	invalidDocSeen := false
	for _, doc := range f.Docs {
		msg := factory()
		uctx := newUnmarshalCtx(doc)

		bodyNode, ok := doc.Body.(ast.MapNode)
		if !ok {
			// ignore commented out documents
			if doc.Body.Type() == ast.CommentType {
				continue
			}

			// If given an invalid file with multiple lines of text, the parser generates a "doc" for each line.
			// Ignore a consecutive run of such docs.
			if invalidDocSeen {
				continue
			}

			outErr = errors.Join(outErr, uctx.perrorf(doc.Body, "invalid document: contents are not valid YAML or JSON"))
			outMsg = append(outMsg, msg)
			outSrc = append(outSrc, uctx.toSourceCtx())
			invalidDocSeen = true
			continue
		}
		invalidDocSeen = false

		if err := u.unmarshalMapping(uctx, bodyNode, msg.ProtoReflect()); err != nil {
			outErr = errors.Join(outErr, err)
		} else if err := u.validate(uctx, msg); err != nil {
			outErr = errors.Join(outErr, err)
		}

		outMsg = append(outMsg, msg)
		outSrc = append(outSrc, uctx.toSourceCtx())
	}

	return outMsg, outSrc, outErr
}

func parse(contents []byte, detectProblems bool) (_ *ast.File, outErr error) {
	t := lexer.Tokenize(unsafe.String(unsafe.SliceData(contents), len(contents)))
	if detectProblems && !util.IsJSON(contents) {
		if errs := detectStringStartingWithQuote(t); len(errs) > 0 {
			for _, err := range errs {
				outErr = errors.Join(outErr, NewUnmarshalError(err))
			}
			return nil, outErr
		}
	}

	return parser.Parse(t, parser.ParseComments)
}

func detectStringStartingWithQuote(tokens token.Tokens) (outErrs []*sourcev1.Error) {
	var errPrinter printer.Printer
	i := 0
	for {
		if i >= len(tokens) {
			break
		}
		tok := tokens[i]

		if tok.Prev != nil && tok.Prev.Type != token.MappingValueType {
			i++
			continue
		}

		if !(tok.Type == token.DoubleQuoteType || tok.Type == token.SingleQuoteType) {
			i++
			continue
		}

		if tok.Next == nil || tok.Next.Position.Line != tok.Position.Line {
			i++
			continue
		}

		i++
		invalid := false
		for t := tok.Next; t != nil && t.Position.Line == tok.Position.Line; t = t.Next {
			switch t.Type {
			case token.CollectEntryType, token.CommentType, token.AnchorType:
			default:
				invalid = true
			}
			i++
		}

		if invalid {
			outErrs = append(outErrs, &sourcev1.Error{
				Kind:    sourcev1.Error_KIND_PARSE_ERROR,
				Message: "invalid YAML string: use a literal or folded block for strings containing quotes",
				Position: &sourcev1.Position{
					Line:   uint32(tok.Position.Line),
					Column: uint32(tok.Position.Column),
				},
				Context: errPrinter.PrintErrorToken(tok, false),
			})
		}
	}

	return outErrs
}

type unmarshalOpts struct {
	validator           *protovalidate.Validator
	ignoreUnknownFields bool
}

type UnmarshalOpt func(*unmarshalOpts)

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

type unmarshaler[T proto.Message] struct {
	anchors map[string]ast.Node
	unmarshalOpts
}

func (u *unmarshaler[T]) unmarshalMapping(uctx *unmarshalCtx, v ast.MapNode, out protoreflect.Message) error {
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
			return uctx.perrorf(kn, "unexpected key type %s", kn.Type())
		}

		field := fields.ByJSONName(keyValue)
		if field == nil {
			field = fields.ByTextName(keyValue)
		}

		if field == nil {
			if u.ignoreUnknownFields {
				continue
			}
			return uctx.perrorf(kn, "unknown field %q", keyValue)
		}

		if prev, ok := seen[field.Number()]; ok {
			return uctx.perrorf(kn, "duplicate field definition: previous definition at %s", prev)
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
					return uctx.perrorf(kn, "invalid value: oneof field is already set at %s", prev)
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

func (u *unmarshaler[T]) resolveMerge(uctx *unmarshalCtx, n ast.Node) (ast.MapNode, error) {
	if an, ok := n.(*ast.AliasNode); ok {
		anchorName := an.Value.GetToken().Value
		aliased, ok := u.anchors[anchorName]
		if !ok {
			return nil, uctx.perrorf(n, "unknown anchor %q", anchorName)
		}

		mn, ok := aliased.(ast.MapNode)
		if !ok {
			return nil, uctx.perrorf(n, "expected map alias got %s", aliased.Type())
		}

		return mn, nil
	}

	return nil, uctx.perrorf(n, "not an alias")
}

func (u *unmarshaler[T]) resolveNode(uctx *unmarshalCtx, n ast.Node) (ast.Node, error) {
	switch t := n.(type) {
	case *ast.AnchorNode:
		anchorName := t.Name.GetToken().Value
		if u.anchors == nil {
			u.anchors = make(map[string]ast.Node)
			u.anchors[anchorName] = t.Value
			return t.Value, nil
		}

		if _, ok := u.anchors[anchorName]; ok {
			return nil, uctx.perrorf(n, "duplicate anchor definition %q", t.String())
		}

		u.anchors[anchorName] = t.Value
		return t.Value, nil
	case *ast.AliasNode:
		anchorName := t.Value.GetToken().Value
		an, ok := u.anchors[anchorName]
		if !ok {
			return nil, uctx.perrorf(n, "unknown anchor %q", anchorName)
		}

		return an, nil
	case *ast.TagNode:
		return t.Value, nil
	default:
		return n, nil
	}
}

func (u *unmarshaler[T]) unmarshalList(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor, list protoreflect.List) error {
	nn, err := u.resolveNode(uctx, n)
	if err != nil {
		return err
	}

	sn, ok := nn.(*ast.SequenceNode)
	if !ok {
		return uctx.perrorf(n, "expected sequence got %s", nn.Type())
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

func (u *unmarshaler[T]) unmarshalMap(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor, mmap protoreflect.Map) error {
	nn, err := u.resolveNode(uctx, n)
	if err != nil {
		return err
	}

	mn, ok := nn.(ast.MapNode)
	if !ok {
		return uctx.perrorf(n, "expected map got %s", nn.Type())
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
			return uctx.perrorf(items.Key(), "duplicate map key")
		}

		val, err := valueFn(uctx.forMapItem(key.String(), items.Key()), items.Value())
		if err != nil {
			return err
		}

		mmap.Set(key, val)
	}

	return nil
}

func (u *unmarshaler[T]) unmarshalSingular(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor, out protoreflect.Message) error {
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

func (u *unmarshaler[T]) unmarshalScalar(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
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
		return protoreflect.Value{}, uctx.perrorf(n, "unknown scalar type")
	}
}

func (u *unmarshaler[T]) unmarshalBool(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
	bn, ok := n.(*ast.BoolNode)
	if !ok {
		return protoreflect.Value{}, uctx.perrorf(n, "expected boolean value got %s", n.Type())
	}

	return protoreflect.ValueOfBool(bn.Value), nil
}

func (u *unmarshaler[T]) unmarshalEnum(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	switch t := n.(type) {
	case *ast.StringNode:
		if ev := fd.Enum().Values().ByName(protoreflect.Name(t.Value)); ev != nil {
			return protoreflect.ValueOfEnum(ev.Number()), nil
		}
		return protoreflect.Value{}, uctx.perrorf(n, "invalid enum value %q", t.Value)
	case *ast.IntegerNode:
		switch tv := t.Value.(type) {
		case uint64:
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(tv)), nil
		case int64:
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(tv)), nil
		default:
			return protoreflect.Value{}, uctx.perrorf(n, "invalid enum value %q", t.Value)
		}
	case *ast.NullNode:
		return protoreflect.ValueOfEnum(0), nil
	default:
		return protoreflect.Value{}, uctx.perrorf(n, "invalid enum value")
	}
}

func (u *unmarshaler[T]) unmarshalString(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, uctx.perrorf(n, "unexpected integer value %q", t.Value)
		}
	case *ast.BoolNode:
		return protoreflect.ValueOf(t.String()), nil
	default:
		return protoreflect.Value{}, uctx.perrorf(n, "expected string value got %s", n.Type())
	}
}

//nolint:dupl
func (u *unmarshaler[T]) unmarshalInt(uctx *unmarshalCtx, n ast.Node, bitSize int) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, uctx.perrorf(n, "invalid integer value %q", t.Value)
		}
	case *ast.StringNode:
		s := strings.TrimSpace(t.Value)
		v, err := strconv.ParseInt(s, base10, bitSize)
		if err != nil {
			return protoreflect.Value{}, uctx.perrorf(n, "invalid integer value %q: %v", v, err)
		}
		if bitSize == bitSize32 {
			return protoreflect.ValueOfInt32(int32(v)), nil
		}
		return protoreflect.ValueOfInt64(v), nil
	default:
		return protoreflect.Value{}, uctx.perrorf(n, "expected integer value got %s", n.Type())
	}
}

//nolint:dupl
func (u *unmarshaler[T]) unmarshalUint(uctx *unmarshalCtx, n ast.Node, bitSize int) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, uctx.perrorf(n, "invalid integer value %q", t.Value)
		}
	case *ast.StringNode:
		s := strings.TrimSpace(t.Value)
		v, err := strconv.ParseUint(s, base10, bitSize)
		if err != nil {
			return protoreflect.Value{}, uctx.perrorf(n, "invalid integer value %q: %v", v, err)
		}
		if bitSize == bitSize32 {
			return protoreflect.ValueOfUint32(uint32(v)), nil
		}
		return protoreflect.ValueOfUint64(v), nil
	default:
		return protoreflect.Value{}, uctx.perrorf(n, "expected integer value got %s", n.Type())
	}
}

func (u *unmarshaler[T]) unmarshalFloat(uctx *unmarshalCtx, n ast.Node, bitSize int) (protoreflect.Value, error) {
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
			return protoreflect.Value{}, uctx.perrorf(n, "invalid float value %q", t.Value)
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
				return protoreflect.Value{}, uctx.perrorf(n, "invalid float value %q: %v", s, err)
			}

			if bitSize == bitSize32 {
				return protoreflect.ValueOfFloat32(float32(v)), nil
			}
			return protoreflect.ValueOfFloat64(v), nil
		}
	default:
		return protoreflect.Value{}, uctx.perrorf(n, "expected float value got %s", n.Type())
	}
}

func (u *unmarshaler[T]) unmarshalBytes(uctx *unmarshalCtx, n ast.Node) (protoreflect.Value, error) {
	var s string
	switch t := n.(type) {
	case *ast.StringNode:
		s = t.Value
	case *ast.LiteralNode:
		s = t.Value.Value
	default:
		return protoreflect.Value{}, uctx.perrorf(n, "expected string value got %s", n.Type())
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
		return protoreflect.Value{}, uctx.perrorf(n, "failed to decode bytes: %v", err)
	}

	return protoreflect.ValueOfBytes(b), nil
}

func (u *unmarshaler[T]) unmarshalMessage(uctx *unmarshalCtx, n ast.Node, out protoreflect.Message) error {
	nn, err := u.resolveNode(uctx, n)
	if err != nil {
		return err
	}

	mn, ok := nn.(ast.MapNode)
	if !ok {
		return uctx.perrorf(n, "expected object got %s", nn.Type())
	}

	return u.unmarshalMapping(uctx, mn, out)
}

func (u *unmarshaler[T]) unmarshalMapKey(uctx *unmarshalCtx, n ast.Node, fd protoreflect.FieldDescriptor) (protoreflect.MapKey, error) {
	sn, ok := n.(*ast.StringNode)
	if !ok {
		return protoreflect.MapKey{}, uctx.perrorf(n, "expected string got %s", n.Type())
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
			return protoreflect.MapKey{}, uctx.perrorf(n, "invalid boolean value %q", sn.Value)
		}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		v, err := strconv.ParseInt(sn.Value, 10, 32)
		if err != nil {
			return protoreflect.MapKey{}, uctx.perrorf(n, "invalid integer value %q: %v", sn.Value, err)
		}
		return protoreflect.ValueOfInt32(int32(v)).MapKey(), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		v, err := strconv.ParseInt(sn.Value, 10, 64)
		if err != nil {
			return protoreflect.MapKey{}, uctx.perrorf(n, "invalid integer value %q: %v", sn.Value, err)
		}
		return protoreflect.ValueOfInt64(v).MapKey(), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		v, err := strconv.ParseUint(sn.Value, 10, 32)
		if err != nil {
			return protoreflect.MapKey{}, uctx.perrorf(n, "invalid integer value %q: %v", sn.Value, err)
		}
		return protoreflect.ValueOfUint32(uint32(v)).MapKey(), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		v, err := strconv.ParseUint(sn.Value, 10, 64)
		if err != nil {
			return protoreflect.MapKey{}, uctx.perrorf(n, "invalid integer value %q: %v", sn.Value, err)
		}
		return protoreflect.ValueOfUint64(v).MapKey(), nil
	default:
		return protoreflect.MapKey{}, uctx.perrorf(n, "unsupported map key type %s", fd.Kind())
	}
}

func (u *unmarshaler[T]) validate(uctx *unmarshalCtx, msg T) (outErr error) {
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

type unmarshalCtx struct {
	errPrinter printer.Printer
	srcCtx     *sourcev1.SourceContext
	doc        *ast.DocumentNode
	protoPath  string
}

func newUnmarshalCtx(doc *ast.DocumentNode) *unmarshalCtx {
	var startPos *sourcev1.StartPosition
	if doc != nil && doc.GetToken() != nil {
		if p := doc.GetToken().Position; p != nil {
			startPos = &sourcev1.StartPosition{Line: uint32(p.Line), Column: uint32(p.Column), Offset: uint32(p.Offset)}
		}
	}

	return &unmarshalCtx{
		doc: doc,
		srcCtx: &sourcev1.SourceContext{
			StartPosition: startPos,
		},
	}
}

func newUnmarshalCtxWithoutSourceCtx(doc *ast.DocumentNode) *unmarshalCtx {
	return &unmarshalCtx{doc: doc}
}

func (uc *unmarshalCtx) forPath(path string) *unmarshalCtx {
	return &unmarshalCtx{
		errPrinter: uc.errPrinter,
		srcCtx:     uc.srcCtx,
		doc:        uc.doc,
		protoPath:  path,
	}
}

func (uc *unmarshalCtx) forField(fd protoreflect.FieldDescriptor, n ast.Node) *unmarshalCtx {
	return uc.forMapItem(string(fd.Name()), n)
}

func (uc *unmarshalCtx) forListItem(i int, n ast.Node) *unmarshalCtx {
	newPath := fmt.Sprintf("%s[%d]", uc.protoPath, i)
	uc.recordFieldPosition(newPath, n)
	return uc.forPath(newPath)
}

func (uc *unmarshalCtx) forMapItem(key string, n ast.Node) *unmarshalCtx {
	var newPath string
	if uc.protoPath != "" {
		newPath = uc.protoPath + "." + key
	} else {
		newPath = key
	}

	uc.recordFieldPosition(newPath, n)
	return uc.forPath(newPath)
}

func (uc *unmarshalCtx) recordFieldPosition(path string, n ast.Node) {
	if uc.srcCtx != nil && n != nil {
		if tok := n.GetToken(); tok != nil && tok.Position != nil {
			if uc.srcCtx.FieldPositions == nil {
				uc.srcCtx.FieldPositions = make(map[string]*sourcev1.Position)
			}

			uc.srcCtx.FieldPositions[path] = &sourcev1.Position{Line: uint32(tok.Position.Line), Column: uint32(tok.Position.Column), Path: n.GetPath()}
		}
	}
}

func (uc *unmarshalCtx) addError(err *sourcev1.Error) {
	if uc.srcCtx != nil {
		uc.srcCtx.Errors = append(uc.srcCtx.Errors, err)
	}
}

func (uc *unmarshalCtx) perrorf(n ast.Node, msg string, args ...any) error {
	err := &sourcev1.Error{Kind: sourcev1.Error_KIND_PARSE_ERROR, Message: fmt.Sprintf(msg, args...)}
	if n == nil {
		uc.addError(err)
		return NewUnmarshalError(err)
	}

	err.Position = &sourcev1.Position{Path: n.GetPath()}
	tok := n.GetToken()
	if tok == nil {
		uc.addError(err)
		return NewUnmarshalError(err)
	}

	var errPrinter printer.Printer
	err.Position.Line = uint32(tok.Position.Line)
	err.Position.Column = uint32(tok.Position.Column)
	err.Context = errPrinter.PrintErrorToken(tok, false)

	uc.addError(err)
	return NewUnmarshalError(err)
}

func (uc *unmarshalCtx) verrorf(path, msg string) error {
	err := &sourcev1.Error{Kind: sourcev1.Error_KIND_VALIDATION_ERROR, Message: fmt.Sprintf("%s: %s", strcase.LowerCamelCase(path), msg)}
	if uc.srcCtx != nil {
		if pos, ok := uc.srcCtx.FieldPositions[path]; ok {
			err.Position = &sourcev1.Position{
				Line:   pos.Line,
				Column: pos.Column,
				Path:   pos.Path,
			}
			err.Context = uc.buildErrContext(pos.Path)
		}

		uc.srcCtx.Errors = append(uc.srcCtx.Errors, err)
	}

	return NewUnmarshalError(err)
}

func (uc *unmarshalCtx) buildErrContext(path string) string {
	if path == "" {
		return ""
	}

	yamlPath, err := yaml.PathString(path)
	if err != nil {
		return ""
	}

	node, err := yamlPath.FilterNode(uc.doc.Body)
	if err != nil {
		return ""
	}

	return uc.errPrinter.PrintErrorToken(node.GetToken(), false)
}

func (uc *unmarshalCtx) toSourceCtx() SourceCtx {
	return newSourceCtx(uc.srcCtx, uc.doc)
}

type UnmarshalError struct {
	Err *sourcev1.Error
}

func NewUnmarshalError(err *sourcev1.Error) UnmarshalError {
	return UnmarshalError{Err: err}
}

func (ue UnmarshalError) Error() string {
	pos := ue.Err.GetPosition()
	if ue.Err.GetContext() == "" {
		return fmt.Sprintf("%d:%d <%s> %s", pos.GetLine(), pos.GetColumn(), pos.GetPath(), ue.Err.GetMessage())
	}

	return fmt.Sprintf("%d:%d <%s> %s\n%s", pos.GetLine(), pos.GetColumn(), pos.GetPath(), ue.Err.GetMessage(), ue.Err.GetContext())
}
