// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

type typeRegistry struct {
	types.Adapter
	types.Provider
}

var (
	_ types.Adapter  = (*typeRegistry)(nil)
	_ types.Provider = (*typeRegistry)(nil)
)

func Registry() cel.EnvOption {
	return func(env *cel.Env) (_ *cel.Env, err error) {
		registry := &typeRegistry{
			Adapter:  env.CELTypeAdapter(),
			Provider: env.CELTypeProvider(),
		}

		env, err = cel.CustomTypeAdapter(registry)(env)
		if err != nil {
			return nil, err
		}

		return cel.CustomTypeProvider(registry)(env)
	}
}

func (r *typeRegistry) FindStructType(structType string) (*types.Type, bool) {
	if structType == variablesTypeName {
		return VariablesType, true
	}

	return r.Provider.FindStructType(structType)
}

func (r *typeRegistry) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	switch structType {
	case runtimeTypeName:
		return runtimeFieldType(fieldName)
	case variablesTypeName:
		return variablesFieldType(fieldName)
	}

	if fieldType, ok := r.Provider.FindStructFieldType(structType, fieldName); ok {
		return fieldType, ok
	}

	messageType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(structType))
	if err != nil {
		return nil, false
	}

	fieldDesc := messageType.Descriptor().Fields().ByJSONName(fieldName)
	if fieldDesc == nil {
		return nil, false
	}

	return r.Provider.FindStructFieldType(structType, string(fieldDesc.Name()))
}

func (r *typeRegistry) NativeToValue(native any) ref.Val {
	return wrapProtoMessage(r.Adapter.NativeToValue(native))
}

// wrapProtoMessage wraps a proto message value so that its fields can be accessed by JSON name.
// Type-checked expressions resolve JSON names at compile time, but unchecked ones (as evaluated by
// the query planner) rely on this.
//
// The check is made on the adapted value, not on the native one. While evaluating `a.b.c`, CEL passes
// each intermediate result through the adapter. A nested message such as `a.b` arrives there as a CEL
// value that the underlying adapter has already built, not as a proto.Message.
func wrapProtoMessage(value ref.Val) ref.Val {
	if _, ok := value.(*protoMessageObject); ok {
		return value
	}

	if t, ok := value.Type().(*types.Type); !ok || t.Kind() != types.StructKind {
		return value
	}

	message, ok := value.Value().(proto.Message)
	if !ok {
		return value
	}

	obj, ok := value.(object)
	if !ok {
		return value
	}

	return &protoMessageObject{
		object: obj,
		fields: message.ProtoReflect().Descriptor().Fields(),
	}
}

type object interface {
	ref.Val
	traits.FieldTester
	traits.Indexer
}

type protoMessageObject struct {
	object
	fields protoreflect.FieldDescriptors
}

func (o *protoMessageObject) IsSet(field ref.Val) ref.Val {
	return o.resolveField(o.object.IsSet, field)
}

func (o *protoMessageObject) Get(index ref.Val) ref.Val {
	return o.resolveField(o.object.Get, index)
}

func (o *protoMessageObject) resolveField(method func(ref.Val) ref.Val, field ref.Val) ref.Val {
	result := method(field)
	if !types.IsError(result) {
		return result
	}

	jsonName, ok := field.(types.String)
	if !ok {
		return result
	}

	fieldDesc := o.fields.ByJSONName(string(jsonName))
	if fieldDesc == nil {
		return result
	}

	return method(types.String(fieldDesc.Name()))
}
