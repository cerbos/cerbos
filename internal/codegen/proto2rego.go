package codegen

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/open-policy-agent/opa/ast"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// MarshalProtoToRego converts a protobuf message into a Rego Value.
func MarshalProtoToRego(p proto.Message) (ast.Value, error) {
	// TODO (cell) Optimize this function. The Proto->JSON->Rego route is surprisingly faster.

	if p == nil {
		return ast.NewObject(), nil
	}

	enc := regoEncoder{}
	return enc.marshalMessage(p.ProtoReflect())
}

type regoEncoder struct{}

func (enc regoEncoder) marshalMessage(msg protoreflect.Message) (ast.Value, error) {
	if msg == nil {
		return ast.NewObject(), nil
	}

	if msg.Descriptor().FullName().Parent() == "google.protobuf" {
		// Google well-known-types have special marshalling logic that is not public.
		// Therefore we go through the proto->json->rego route for those.
		requestJSON, err := protojson.Marshal(msg.Interface())
		if err != nil {
			return nil, err
		}

		return ast.ValueFromReader(bytes.NewReader(requestJSON))
	}

	var topErr error
	var items [][2]*ast.Term

	msg.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		astVal, err := enc.marshalValue(val, fd)
		if err != nil {
			topErr = err
			return false
		}

		items = append(items, [2]*ast.Term{ast.StringTerm(fd.JSONName()), astVal})

		return true
	})

	if topErr != nil {
		return nil, topErr
	}

	return ast.NewObject(items...), nil
}

func (enc regoEncoder) marshalValue(v protoreflect.Value, fd protoreflect.FieldDescriptor) (*ast.Term, error) {
	switch {
	case fd.IsList():
		return enc.marshalList(v.List(), fd)
	case fd.IsMap():
		return enc.marshalMap(v.Map(), fd)
	default:
		return enc.marshalSingular(v, fd)
	}
}

func (enc regoEncoder) marshalList(list protoreflect.List, fd protoreflect.FieldDescriptor) (*ast.Term, error) {
	items := make([]*ast.Term, list.Len())

	for i := 0; i < list.Len(); i++ {
		itm := list.Get(i)
		v, err := enc.marshalSingular(itm, fd)
		if err != nil {
			return nil, err
		}

		items[i] = v
	}

	return ast.ArrayTerm(items...), nil
}

func (enc regoEncoder) marshalMap(m protoreflect.Map, fd protoreflect.FieldDescriptor) (*ast.Term, error) {
	var topErr error
	items := make([][2]*ast.Term, m.Len())
	i := 0

	m.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
		v, err := enc.marshalSingular(value, fd.MapValue())
		if err != nil {
			topErr = err
			return false
		}

		items[i] = [2]*ast.Term{ast.StringTerm(key.String()), v}
		i++

		return true
	})

	return ast.ObjectTerm(items...), topErr
}

func (enc regoEncoder) marshalSingular(val protoreflect.Value, fd protoreflect.FieldDescriptor) (*ast.Term, error) {
	if !val.IsValid() {
		return ast.NullTerm(), nil
	}

	switch fd.Kind() {
	case protoreflect.BoolKind:
		return ast.BooleanTerm(val.Bool()), nil
	case protoreflect.StringKind:
		return ast.StringTerm(val.String()), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		intVal := strconv.FormatInt(val.Int(), 10)
		return ast.NumberTerm(json.Number(intVal)), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		uintVal := strconv.FormatUint(val.Uint(), 10)
		return ast.NumberTerm(json.Number(uintVal)), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind, protoreflect.Sfixed64Kind, protoreflect.Fixed64Kind:
		return ast.NumberTerm(json.Number(val.String())), nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		floatVal := strconv.FormatFloat(val.Float(), 'e', -1, 64)
		return ast.NumberTerm(json.Number(floatVal)), nil
	case protoreflect.BytesKind:
		return ast.StringTerm(base64.StdEncoding.EncodeToString(val.Bytes())), nil
	case protoreflect.EnumKind:
		if fd.Enum().FullName() == "google.protobuf.NullValue" {
			return ast.NullTerm(), nil
		}
		desc := fd.Enum().Values().ByNumber(val.Enum())
		if desc == nil {
			return ast.IntNumberTerm(int(val.Enum())), nil
		}
		return ast.StringTerm(string(desc.Name())), nil
	case protoreflect.MessageKind, protoreflect.GroupKind:
		mval, err := enc.marshalMessage(val.Message())
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(mval), nil
	default:
		return nil, fmt.Errorf("unknown protobuf value kind: %s", fd.Kind().String())
	}
}
