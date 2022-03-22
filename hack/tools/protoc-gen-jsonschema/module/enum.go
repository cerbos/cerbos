// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/jsonschema"
	"github.com/envoyproxy/protoc-gen-validate/validate"
	pgs "github.com/lyft/protoc-gen-star"
)

func (m *Module) defineEnum(enum pgs.Enum) *jsonschema.StringSchema {
	schema := jsonschema.NewStringSchema()

	for _, value := range enum.Values() {
		schema.Enum = append(schema.Enum, value.Name().String())
	}

	return schema
}

func (m *Module) schemaForEnum(enum pgs.Enum, rules *validate.EnumRules) (jsonschema.Schema, bool) {
	if rules != nil {
		switch {
		case rules.Const != nil:
			return m.schemaForEnumConst(enum, rules.GetConst())
		case len(rules.In) > 0:
			return m.schemaForEnumIn(enum, rules.In)
		case len(rules.NotIn) > 0:
			return m.schemaForEnumNotIn(enum, rules.NotIn)
		}
	}

	return m.enumRef(enum), false
}

func (m *Module) schemaForEnumConst(enum pgs.Enum, value int32) (*jsonschema.StringSchema, bool) {
	schema := jsonschema.NewStringSchema()
	schema.Const = jsonschema.String(m.lookUpEnumName(enum, value))
	return schema, value != 0
}

func (m *Module) schemaForEnumIn(enum pgs.Enum, values []int32) (*jsonschema.StringSchema, bool) {
	schema := jsonschema.NewStringSchema()
	required := true

	for _, value := range values {
		schema.Enum = append(schema.Enum, m.lookUpEnumName(enum, value))
		if value == 0 {
			required = false
		}
	}
	return schema, required
}

func (m *Module) schemaForEnumNotIn(enum pgs.Enum, values []int32) (*jsonschema.StringSchema, bool) {
	exclude := make(map[int32]struct{}, len(values))
	for _, v := range values {
		exclude[v] = struct{}{}
	}

	schema := jsonschema.NewStringSchema()
	required := true

	for _, v := range enum.Values() {
		value := v.Value()
		if _, ok := exclude[value]; !ok {
			schema.Enum = append(schema.Enum, v.Name().String())
			if value == 0 {
				required = false
			}
		}
	}

	return schema, required
}

func (m *Module) lookUpEnumName(enum pgs.Enum, value int32) string {
	for _, enumValue := range enum.Values() {
		if enumValue.Value() == value {
			return enumValue.Name().String()
		}
	}

	m.Failf("unknown enum value %d", value)
	return ""
}

func (m *Module) enumRef(enum pgs.Enum) *jsonschema.GenericSchema {
	return m.ref(enum, func() jsonschema.Schema {
		return m.defineEnum(enum)
	})
}
