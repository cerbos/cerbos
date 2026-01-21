// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
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
	value := r.Adapter.NativeToValue(native)
	if message, ok := native.(proto.Message); ok {
		if obj, ok := value.(object); ok {
			return &protoMessageObject{
				object: obj,
				fields: message.ProtoReflect().Descriptor().Fields(),
			}
		}
	}

	return value
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
