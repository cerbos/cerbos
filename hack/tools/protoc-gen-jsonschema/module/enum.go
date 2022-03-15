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
	required := false
	schemas := []jsonschema.NonTrivialSchema{m.enumRef(enum)}

	if rules != nil {
		if rules.Const != nil {
			schemas = append(schemas, m.schemaForEnumConst(enum, rules.GetConst()))
			required = true
		}

		if len(rules.In) > 0 {
			schemas = append(schemas, m.schemaForEnumIn(enum, rules.In))
			required = true
		}

		if len(rules.NotIn) > 0 {
			schemas = append(schemas, jsonschema.Not(m.schemaForEnumIn(enum, rules.NotIn)))
		}
	}

	return jsonschema.AllOf(schemas...), required
}

func (m *Module) schemaForEnumConst(enum pgs.Enum, value int32) *jsonschema.StringSchema {
	schema := jsonschema.NewStringSchema()
	schema.Const = jsonschema.String(m.lookUpEnumName(enum, value))
	return schema
}

func (m *Module) schemaForEnumIn(enum pgs.Enum, values []int32) *jsonschema.StringSchema {
	schema := jsonschema.NewStringSchema()
	for _, value := range values {
		schema.Enum = append(schema.Enum, m.lookUpEnumName(enum, value))
	}
	return schema
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
