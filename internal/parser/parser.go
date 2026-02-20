// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
	"github.com/goccy/go-yaml/token"
	"github.com/stoewer/go-strcase"
	"google.golang.org/protobuf/encoding/protojson"
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

type PanicError struct {
	Cause   any
	Context []byte
}

func (pe PanicError) Error() string {
	return fmt.Sprintf("panic: %v", pe.Cause)
}

var protoErrPrefix = regexp.MustCompile(`proto:(\x{00a0}|\x{0020})+\(line\s+\d+:\d+\):\s*`)

// Find a single document from the multi-document stream.
// TODO(cell): Optimize!
// For our use case, this could be optimized by storing the offset of each document and directly seeking to that offset.
// However, there are a couple of problems with that:
//  1. The offsets reported by the parser are not always reliable (I am yet to figure out why)
//  2. If YAML anchors have been used, we need to resolve those first by reading through the entire file anyway
//     However, this is a relatively niche case and we can handle that case lazily (seek first, read, and resolve anchors only if they exist in the doc)
//
// In the interest of time, I am leaving those optimizations for later.
func Find[T proto.Message](r io.Reader, match func(T) bool, out T, opts ...UnmarshalOpt) (SourceCtx, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return SourceCtx{}, fmt.Errorf("failed to read contents: %w", err)
	}

	f, err := parse(contents, false)
	if err != nil {
		return SourceCtx{}, err
	}

	if len(f.Docs) == 0 {
		return SourceCtx{}, ErrNotFound
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
		uctx := newUnmarshalCtx(doc)

		if err := u.unmarshalMapping(uctx, bodyNode, refOut); err != nil {
			continue
		}

		if !match(out) {
			continue
		}

		return uctx.toSourceCtx(), u.validate(uctx, out)
	}

	return SourceCtx{}, ErrNotFound
}

func Unmarshal[T proto.Message](r io.Reader, factory func() T, opts ...UnmarshalOpt) ([]T, []SourceCtx, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read contents: %w", err)
	}

	return UnmarshalBytes(contents, factory, opts...)
}

func UnmarshalBytes[T proto.Message](contents []byte, factory func() T, opts ...UnmarshalOpt) (_ []T, _ []SourceCtx, outErr error) {
	contentLen := len(bytes.TrimSpace(contents))
	if contentLen == 0 {
		return nil, nil, nil
	}

	f, err := parse(contents, true)
	if err != nil {
		return nil, nil, err
	}

	if len(f.Docs) == 0 {
		return nil, nil, NewUnmarshalError(&sourcev1.Error{
			Kind:     sourcev1.Error_KIND_PARSE_ERROR,
			Message:  "invalid document: contents are not valid YAML or JSON",
			Position: &sourcev1.Position{Line: 1, Column: 1, Path: "$"},
		})
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
	defer func() {
		if r := recover(); r != nil {
			outErr = PanicError{Cause: r, Context: contents}
		}
	}()

	t := lexer.Tokenize(unsafe.String(unsafe.SliceData(contents), len(contents)))
	if detectProblems && !util.IsJSON(contents) {
		if errs := detectStringStartingWithQuote(t); len(errs) > 0 {
			for _, err := range errs {
				outErr = errors.Join(outErr, NewUnmarshalError(err))
			}
			return nil, outErr
		}
	}

	file, err := parser.Parse(t, parser.ParseComments)
	if err != nil { //nolint:nestif
		syntaxErr := new(yaml.SyntaxError)
		if errors.As(err, &syntaxErr) {
			srcErr := &sourcev1.Error{
				Kind:    sourcev1.Error_KIND_PARSE_ERROR,
				Message: syntaxErr.Message,
			}
			if syntaxErr.Token != nil {
				if syntaxErr.Token.Position != nil {
					srcErr.Position = &sourcev1.Position{
						Line:   uint32(syntaxErr.Token.Position.Line),
						Column: uint32(syntaxErr.Token.Position.Column),
					}
				}
				var errPrinter printer.Printer
				srcErr.Context = errPrinter.PrintErrorToken(syntaxErr.Token, false)
			}

			return file, NewUnmarshalError(srcErr)
		}
	}
	return file, err
}

func detectStringStartingWithQuote(tokens token.Tokens) (outErrs []*sourcev1.Error) {
	var errPrinter printer.Printer
	i := 0
	flowBlock := 0
	for i < len(tokens) {
		tok := tokens[i]

		// Check whether we are inside a flow block (e.g. foo: {"x": "y"})
		if tok.Indicator == token.FlowCollectionIndicator {
			if tok.Type == token.MappingStartType || tok.Type == token.SequenceStartType {
				flowBlock++
			} else {
				flowBlock--
			}
		}

		if flowBlock > 0 {
			i++
			continue
		}

		if tok.Prev != nil && tok.Prev.Type != token.MappingValueType {
			i++
			continue
		}

		if tok.Type != token.DoubleQuoteType && tok.Type != token.SingleQuoteType {
			i++
			continue
		}

		if tok.Next == nil || tok.Next.Type == token.MappingValueType || tok.Next.Position.Line != tok.Position.Line {
			i++
			continue
		}

		i++
		invalid := false
		for t := tok.Next; t != nil && t.Position.Line == tok.Position.Line; t = t.Next {
			switch t.Type {
			case token.CollectEntryType, token.CommentType, token.AnchorType, token.MappingEndType:
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
	validator           protovalidate.Validator
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
func WithValidator(validator protovalidate.Validator) UnmarshalOpt {
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

	// Find all the merge keys first and populate the message because they need to overwritten by new values
	// Basically, ensuring that "bar" is set to "baz" in the following case regardless of what value "bar" has
	// in the "anchor" map.
	// x:
	//  bar: baz
	//  <<: *anchor
	for items.Next() {
		if items.Key().Type() == ast.MergeKeyType {
			mn, err := u.resolveMerge(uctx, items.Value())
			if err != nil {
				return err
			}

			if err := u.unmarshalMapping(uctx, mn, out); err != nil {
				return err
			}
		}
	}

	items = v.MapRange()
	for items.Next() {
		kn := items.Key()

		var keyValue string
		switch kt := kn.(type) {
		case *ast.StringNode:
			keyValue = kt.Value
		case *ast.MergeKeyNode:
			// already handled above
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

			nn, err := u.resolveNode(uctx, items.Value())
			if err != nil {
				return err
			}

			mn, ok := nn.(ast.MapNode)
			if !ok {
				return uctx.perrorf(items.Value(), "expected map got %s", nn.Type())
			}

			if err := u.unmarshalMap(uctx.forField(field, kn), mn, field, mmap, true); err != nil {
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

		resolved, err := u.resolveAlias(uctx, aliased)
		if err != nil {
			return nil, err
		}

		mn, ok := resolved.(ast.MapNode)
		if !ok {
			return nil, uctx.perrorf(n, "expected map alias got %s", resolved.Type())
		}

		return mn, nil
	}

	return nil, uctx.perrorf(n, "not an alias")
}

func (u *unmarshaler[T]) resolveNode(uctx *unmarshalCtx, n ast.Node) (ast.Node, error) {
	switch t := n.(type) {
	case *ast.AnchorNode:
		anchorName := t.Name.GetToken().Value
		if _, ok := u.anchors[anchorName]; ok {
			return nil, uctx.perrorf(n, "duplicate anchor definition %q", t.String())
		}

		if u.anchors == nil {
			u.anchors = make(map[string]ast.Node)
		}
		u.anchors[anchorName] = t.Value
		return u.resolveNode(uctx, t.Value)
	case *ast.AliasNode:
		anchorName := t.Value.GetToken().Value
		an, ok := u.anchors[anchorName]
		if !ok {
			return nil, uctx.perrorf(n, "unknown anchor %q", anchorName)
		}

		return u.resolveAlias(uctx, an)
	case *ast.TagNode:
		return u.resolveAlias(uctx, t.Value)
	default:
		return n, nil
	}
}

// adapted from https://github.com/goccy/go-yaml/blob/31fe1baacec127337140701face2e64a356075fd/decode.go#L355
func (u *unmarshaler[T]) resolveAlias(uctx *unmarshalCtx, n ast.Node) (ast.Node, error) {
	switch nn := n.(type) {
	case *ast.AnchorNode:
		return u.resolveAlias(uctx, nn.Value)
	case *ast.MappingNode:
		for idx, v := range nn.Values {
			value, err := u.resolveAlias(uctx, v)
			if err != nil {
				return nil, err
			}

			vv, ok := value.(*ast.MappingValueNode)
			if !ok {
				return nil, uctx.perrorf(vv, "unexpected node type %s", vv.Type())
			}
			nn.Values[idx] = vv
		}
	case *ast.TagNode:
		value, err := u.resolveAlias(uctx, nn.Value)
		if err != nil {
			return nil, err
		}
		nn.Value = value
	case *ast.MappingKeyNode:
		value, err := u.resolveAlias(uctx, nn.Value)
		if err != nil {
			return nil, err
		}
		nn.Value = value
	case *ast.MappingValueNode:
		//nolint:nestif
		if nn.Key.Type() == ast.MergeKeyType && nn.Value.Type() == ast.AliasType {
			value, err := u.resolveAlias(uctx, nn.Value)
			if err != nil {
				return nil, err
			}
			keyColumn := nn.Key.GetToken().Position.Column
			requiredColumn := keyColumn + 2 //nolint:mnd
			value.AddColumn(requiredColumn)
			nn.Value = value
		} else {
			key, err := u.resolveAlias(uctx, nn.Key)
			if err != nil {
				return nil, err
			}

			k, ok := key.(ast.MapKeyNode)
			if !ok {
				return nil, uctx.perrorf(key, "unexpected node type %s", key.Type())
			}
			nn.Key = k
			value, err := u.resolveAlias(uctx, nn.Value)
			if err != nil {
				return nil, err
			}
			nn.Value = value
		}
	case *ast.SequenceNode:
		for idx, v := range nn.Values {
			value, err := u.resolveAlias(uctx, v)
			if err != nil {
				return nil, err
			}
			nn.Values[idx] = value
		}
	case *ast.AliasNode:
		aliasName := nn.Value.GetToken().Value
		node, ok := u.anchors[aliasName]
		if !ok {
			return nil, uctx.perrorf(n, "unknown alias %s", aliasName)
		}
		return u.resolveAlias(uctx, node)
	}

	return n, nil
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

func (u *unmarshaler[T]) unmarshalMap(uctx *unmarshalCtx, n ast.MapNode, fd protoreflect.FieldDescriptor, mmap protoreflect.Map, overwriteKeys bool) error {
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

	items := n.MapRange()
	for items.Next() {
		key := items.Key()
		if key.Type() == ast.MergeKeyType {
			kn, err := u.resolveMerge(uctx, items.Value())
			if err != nil {
				return err
			}

			if err := u.unmarshalMap(uctx, kn, fd, mmap, false); err != nil {
				return err
			}

			continue
		}

		keyVal, err := u.unmarshalMapKey(uctx, key, fd.MapKey())
		if err != nil {
			return err
		}

		if !overwriteKeys && mmap.Has(keyVal) {
			continue
		}

		val, err := valueFn(uctx.forMapItem(keyVal.String(), key, items.Value()), items.Value())
		if err != nil {
			return err
		}

		mmap.Set(keyVal, val)
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
			return protoreflect.Value{}, uctx.perrorf(n, "invalid integer value %q: %v", s, err)
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
			return protoreflect.Value{}, uctx.perrorf(n, "invalid integer value %q: %v", s, err)
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

	if out.Descriptor().FullName().Parent() == "google.protobuf" {
		return u.unmarshalWKT(uctx, n, out)
	}

	mn, ok := nn.(ast.MapNode)
	if !ok {
		return uctx.perrorf(n, "expected object got %s", nn.Type())
	}

	return u.unmarshalMapping(uctx, mn, out)
}

func (u *unmarshaler[T]) unmarshalWKT(uctx *unmarshalCtx, n ast.Node, out protoreflect.Message) error {
	// Google's well-known type handling is hidden inside an internal package and can't be used directly.
	// The code is complicated and copying it here is probably not a good idea.
	// Cerbos policies don't use any WKTs. Only the test suite definitions and fixtures use them so
	// resorting to this slightly inefficient hack is OK for now.
	nodeStr := n.String()
	jsonBytes, err := yaml.YAMLToJSON(unsafe.Slice(unsafe.StringData(nodeStr), len(nodeStr)))
	if err != nil {
		return uctx.perrorf(n, "failed to convert well-known type: %v", err)
	}

	if err := protojson.Unmarshal(jsonBytes, out.Interface()); err != nil {
		errStr := protoErrPrefix.ReplaceAllString(err.Error(), "")
		return uctx.perrorf(n, "failed to parse value: %s", errStr)
	}

	return nil
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
		path := fieldPathString(v.Proto.GetField().GetElements())
		outErr = errors.Join(outErr, uctx.verrorf(path, v.Proto.GetMessage()))
	}

	return outErr
}

// Taken from https://github.com/bufbuild/protovalidate-go/blob/46121307d89af5b7ae07e27a58d1c2ac26845388/internal/errors/utils.go#L133
func fieldPathString(path []*validate.FieldPathElement) string {
	var result strings.Builder
	for i, element := range path {
		if i > 0 {
			result.WriteByte('.')
		}
		result.WriteString(element.GetFieldName())
		subscript := element.GetSubscript()
		if subscript == nil {
			continue
		}
		result.WriteByte('[')
		switch value := subscript.(type) {
		case *validate.FieldPathElement_Index:
			result.WriteString(strconv.FormatUint(value.Index, 10))
		case *validate.FieldPathElement_BoolKey:
			result.WriteString(strconv.FormatBool(value.BoolKey))
		case *validate.FieldPathElement_IntKey:
			result.WriteString(strconv.FormatInt(value.IntKey, 10))
		case *validate.FieldPathElement_UintKey:
			result.WriteString(strconv.FormatUint(value.UintKey, 10))
		case *validate.FieldPathElement_StringKey:
			result.WriteString(strconv.Quote(value.StringKey))
		}
		result.WriteByte(']')
	}
	return result.String()
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

func (uc *unmarshalCtx) forPath(path string) *unmarshalCtx {
	return &unmarshalCtx{
		errPrinter: uc.errPrinter,
		srcCtx:     uc.srcCtx,
		doc:        uc.doc,
		protoPath:  path,
	}
}

func (uc *unmarshalCtx) forField(fd protoreflect.FieldDescriptor, n ast.Node) *unmarshalCtx {
	var newPath string
	if uc.protoPath != "" {
		newPath = uc.protoPath + "." + string(fd.Name())
	} else {
		newPath = string(fd.Name())
	}

	uc.recordFieldPosition(newPath, n)
	return uc.forPath(newPath)
}

func (uc *unmarshalCtx) forListItem(i int, n ast.Node) *unmarshalCtx {
	newPath := fmt.Sprintf("%s[%d]", uc.protoPath, i)
	uc.recordFieldPosition(newPath, n)
	return uc.forPath(newPath)
}

func (uc *unmarshalCtx) forMapItem(key string, keyNode ast.MapKeyNode, valueNode ast.Node) *unmarshalCtx {
	newPath := fmt.Sprintf("%s[%q]", uc.protoPath, key)
	uc.recordMapKeyPosition(newPath, keyNode)
	uc.recordFieldPosition(newPath, valueNode)
	return uc.forPath(newPath)
}

func (uc *unmarshalCtx) recordMapKeyPosition(path string, n ast.Node) {
	if uc.srcCtx != nil {
		if pos := nodePosition(n); pos != nil {
			if uc.srcCtx.MapKeyPositions == nil {
				uc.srcCtx.MapKeyPositions = make(map[string]*sourcev1.Position)
			}

			uc.srcCtx.MapKeyPositions[path] = pos
		}
	}
}

func (uc *unmarshalCtx) recordFieldPosition(path string, n ast.Node) {
	if uc.srcCtx != nil {
		if pos := nodePosition(n); pos != nil {
			if uc.srcCtx.FieldPositions == nil {
				uc.srcCtx.FieldPositions = make(map[string]*sourcev1.Position)
			}

			uc.srcCtx.FieldPositions[path] = pos
		}
	}
}

func nodePosition(n ast.Node) *sourcev1.Position {
	if n == nil {
		return nil
	}

	tok := n.GetToken()
	if tok == nil || tok.Position == nil {
		return nil
	}

	return &sourcev1.Position{
		Line:   uint32(tok.Position.Line),
		Column: uint32(tok.Position.Column),
		Path:   n.GetPath(),
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
	return ue.StringWithoutContext()
}

func (ue UnmarshalError) StringWithoutContext() string {
	pos := ue.Err.GetPosition()
	if pos != nil {
		return fmt.Sprintf("%d:%d %s", pos.GetLine(), pos.GetColumn(), ue.Err.GetMessage())
	}

	return ue.Err.GetMessage()
}

func (ue UnmarshalError) Format(state fmt.State, verb rune) {
	switch verb {
	case 's':
		fmt.Fprint(state, ue.StringWithoutContext())
	case 'q':
		fmt.Fprintf(state, "%q", ue.StringWithoutContext())
	case 'v':
		switch {
		case state.Flag('+'):
			fmt.Fprintf(state, "%s\n%s", ue.StringWithoutContext(), ue.Err.GetContext())
		case state.Flag('#'):
			fmt.Fprintf(state, "%T %s", ue, ue.StringWithoutContext())
		default:
			fmt.Fprint(state, ue.StringWithoutContext())
		}
	}
}
