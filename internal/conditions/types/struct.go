// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"google.golang.org/protobuf/proto"
)

var (
	byteType         = reflect.TypeFor[byte]()
	durationType     = reflect.TypeFor[time.Duration]()
	errorType        = reflect.TypeFor[error]()
	protoMessageType = reflect.TypeFor[proto.Message]()
	timestampType    = reflect.TypeFor[time.Time]()
)

type structTypeProvider struct {
	types.Provider
	structTypes map[string]*types.Type
	fieldTypes  map[string]*types.FieldType
}

func StructTypes(structTypes ...*StructType) cel.EnvOption {
	return func(env *cel.Env) (*cel.Env, error) {
		provider := &structTypeProvider{
			Provider:    env.CELTypeProvider(),
			structTypes: make(map[string]*types.Type, len(structTypes)),
			fieldTypes:  make(map[string]*types.FieldType),
		}

		for _, structType := range structTypes {
			typeName := structType.Type.TypeName()
			provider.structTypes[typeName] = structType.Type

			fieldTypes, err := structType.fieldTypes()
			if err != nil {
				return nil, err
			}

			for fieldName, fieldType := range fieldTypes {
				provider.fieldTypes[typeName+"."+fieldName] = fieldType
			}
		}

		return cel.CustomTypeProvider(provider)(env)
	}
}

func (p *structTypeProvider) FindStructType(typeName string) (*types.Type, bool) {
	if structType, ok := p.structTypes[typeName]; ok {
		return structType, true
	}

	return p.Provider.FindStructType(typeName)
}

func (p *structTypeProvider) FindStructFieldType(typeName, fieldName string) (*types.FieldType, bool) {
	if fieldType, ok := p.fieldTypes[typeName+"."+fieldName]; ok {
		return fieldType, true
	}

	return p.Provider.FindStructFieldType(typeName, fieldName)
}

type StructType struct {
	Type        *types.Type
	reflectType reflect.Type
}

func NewStructType(from any) *StructType {
	reflectType := reflect.TypeOf(from)
	if reflectType.Kind() != reflect.Struct {
		panic(fmt.Errorf("%T is not a struct", from))
	}

	return &StructType{
		Type:        types.NewObjectType(structTypeName(reflectType)),
		reflectType: reflectType,
	}
}

func (t *StructType) fieldTypes() (map[string]*types.FieldType, error) {
	n := t.reflectType.NumField()
	fieldTypes := make(map[string]*types.FieldType, n)

	for fieldIndex := range n {
		field := t.reflectType.Field(fieldIndex)

		if !field.IsExported() {
			continue
		}

		fieldName, ok := field.Tag.Lookup("cel")
		if !ok {
			continue
		}

		fieldType, call, ok := convertToCelTypeAllowingFunctions(field.Type)
		if !ok {
			return nil, fmt.Errorf("failed to convert type of %s.%s from reflect to CEL", t.Type.TypeName(), fieldName)
		}

		fieldTypes[fieldName] = &types.FieldType{
			Type:  fieldType,
			IsSet: func(target any) bool { return true },
			GetFrom: func(target any) (any, error) {
				var err error
				value := reflect.Indirect(reflect.ValueOf(target)).Field(fieldIndex)
				if call != nil {
					value, err = call(value)
				}
				return value.Interface(), err
			},
		}
	}

	return fieldTypes, nil
}

func structTypeName(reflectType reflect.Type) string {
	pkg := reflectType.PkgPath()

	if lastSlash := strings.LastIndex(pkg, "/"); lastSlash >= 0 {
		pkg = pkg[lastSlash+1:]
	}

	return pkg + "." + reflectType.Name()
}

func convertToCelTypeAllowingFunctions(reflectType reflect.Type) (*types.Type, func(reflect.Value) (reflect.Value, error), bool) {
	if reflectType.Kind() == reflect.Func {
		if reflectType.NumIn() > 0 {
			return nil, nil, false
		}

		switch reflectType.NumOut() {
		case 1:
			outType, ok := convertToCelType(reflectType.Out(0))
			return outType, call1, ok

		case 2:
			if !reflectType.Out(1).Implements(errorType) {
				return nil, nil, false
			}
			outType, ok := convertToCelType(reflectType.Out(0))
			return outType, call2, ok

		default:
			return nil, nil, false
		}
	}

	celType, ok := convertToCelType(reflectType)
	return celType, nil, ok
}

func call1(fn reflect.Value) (reflect.Value, error) {
	return fn.Call(nil)[0], nil
}

func call2(fn reflect.Value) (reflect.Value, error) {
	out := fn.Call(nil)
	var err error
	if !out[1].IsNil() {
		err = out[1].Interface().(error)
	}
	return out[0], err
}

// Adapted from https://github.com/google/cel-go/blob/6024823ef1ef2edd392aab713ded91b7beb8f740/ext/native.go#L397-L448
func convertToCelType(reflectType reflect.Type) (*types.Type, bool) {
	switch reflectType.Kind() {
	case reflect.Bool:
		return types.BoolType, true

	case reflect.Float32, reflect.Float64:
		return types.DoubleType, true

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if reflectType == durationType {
			return types.DurationType, true
		}
		return types.IntType, true

	case reflect.String:
		return types.StringType, true

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return types.UintType, true

	case reflect.Array, reflect.Slice:
		reflectElem := reflectType.Elem()
		if reflectElem == byteType {
			return types.BytesType, true
		}
		elemType, ok := convertToCelType(reflectElem)
		if !ok {
			return nil, false
		}
		return types.NewListType(elemType), true

	case reflect.Map:
		keyType, ok := convertToCelType(reflectType.Key())
		if !ok {
			return nil, false
		}
		elemType, ok := convertToCelType(reflectType.Elem())
		if !ok {
			return nil, false
		}
		return types.NewMapType(keyType, elemType), true

	case reflect.Struct:
		if reflectType == timestampType {
			return types.TimestampType, true
		}
		return types.NewObjectType(structTypeName(reflectType)), true

	case reflect.Pointer:
		if reflectType.Implements(protoMessageType) {
			message := reflect.New(reflectType.Elem()).Interface().(proto.Message)
			return types.NewObjectType(string(message.ProtoReflect().Descriptor().FullName())), true
		}
		return convertToCelType(reflectType.Elem())

	default:
		return nil, false
	}
}
