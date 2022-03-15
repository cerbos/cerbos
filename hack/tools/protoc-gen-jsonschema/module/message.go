// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"fmt"

	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/jsonschema"
	"github.com/envoyproxy/protoc-gen-validate/validate"
	pgs "github.com/lyft/protoc-gen-star"
)

func (m *Module) defineMessage(message pgs.Message) jsonschema.NonTrivialSchema {
	m.pushMessage(message)

	schema := jsonschema.NewObjectSchema()
	schema.AdditionalProperties = jsonschema.False
	schemas := []jsonschema.NonTrivialSchema{schema}

	for _, field := range message.Fields() {
		name := m.propertyName(field)
		valueSchema, required := m.schemaForField(field)
		schema.Properties[name] = valueSchema
		if required {
			schema.Required = append(schema.Required, name)
		}
	}

	for _, oneOf := range message.OneOfs() {
		oneOfSchema := m.schemaForOneOf(oneOf)
		if oneOfSchema != nil {
			schemas = append(schemas, oneOfSchema)
		}
	}

	result := jsonschema.AllOf(schemas...)
	m.popMessage(message, result)
	return result
}

func (m *Module) propertyName(field pgs.Field) string {
	return field.Name().LowerCamelCase().String()
}

func (m *Module) schemaForField(field pgs.Field) (jsonschema.Schema, bool) {
	m.Push(fmt.Sprintf("field:%s", field.Name()))
	defer m.Pop()

	rules := &validate.FieldRules{}
	_, err := field.Extension(validate.E_Rules, rules)
	m.CheckErr(err, "unable to read validation rules from field")

	var schema jsonschema.Schema
	var required bool

	switch {
	case field.Type().IsEmbed():
		schema, required = m.schemaForEmbed(field.Type().Embed(), rules)

	case field.Type().IsEnum():
		schema, required = m.schemaForEnum(field.Type().Enum(), rules.GetEnum())

	case field.Type().IsMap():
		schema, required = m.schemaForMap(field.Type().Element(), rules.GetMap())

	case field.Type().IsRepeated():
		schema, required = m.schemaForRepeated(field.Type().Element(), rules.GetRepeated())

	default:
		schema, required = m.schemaForScalar(field.Type().ProtoType(), rules)
	}

	return schema, required && !field.InOneOf()
}

func (m *Module) schemaForEmbed(embed pgs.Message, rules *validate.FieldRules) (jsonschema.Schema, bool) {
	if embed.IsWellKnown() {
		return m.schemaForWellKnownType(embed.WellKnownType(), rules)
	}

	return m.schemaForMessage(embed, rules.GetMessage())
}

func (m *Module) schemaForMessage(message pgs.Message, rules *validate.MessageRules) (jsonschema.Schema, bool) {
	return m.messageRef(message), rules.GetRequired()
}

func (m *Module) schemaForOneOf(oneOf pgs.OneOf) jsonschema.NonTrivialSchema {
	required := false
	_, err := oneOf.Extension(validate.E_Required, &required)
	m.CheckErr(err, "unable to read required option from oneof")

	if !required {
		return nil
	}

	schemas := make([]jsonschema.NonTrivialSchema, len(oneOf.Fields()))
	for i, field := range oneOf.Fields() {
		schema := jsonschema.NewObjectSchema()
		schema.Required = []string{m.propertyName(field)}
		schemas[i] = schema
	}

	return jsonschema.OneOf(schemas...)
}

func (m *Module) messageRef(message pgs.Message) jsonschema.Schema {
	return m.ref(message, func() jsonschema.Schema {
		return m.defineMessage(message)
	})
}
