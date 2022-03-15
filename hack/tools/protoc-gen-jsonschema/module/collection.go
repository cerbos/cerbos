// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/jsonschema"
	"github.com/envoyproxy/protoc-gen-validate/validate"
	pgs "github.com/lyft/protoc-gen-star"
)

func (m *Module) schemaForMap(value pgs.FieldTypeElem, rules *validate.MapRules) (jsonschema.Schema, bool) {
	required := false
	schema := jsonschema.NewObjectSchema()
	schema.AdditionalProperties, _ = m.schemaForElement(value, rules.GetValues())

	if rules != nil {
		if rules.GetKeys().GetString_() != nil {
			schema.PropertyNames, _ = m.schemaForString(rules.GetKeys().GetString_())
		}

		if rules.MaxPairs != nil {
			schema.MaxProperties = jsonschema.Size(rules.GetMaxPairs())
		}

		if rules.MinPairs != nil {
			schema.MinProperties = jsonschema.Size(rules.GetMinPairs())
			required = !rules.GetIgnoreEmpty()
		}
	}

	return schema, required
}

func (m *Module) schemaForRepeated(item pgs.FieldTypeElem, rules *validate.RepeatedRules) (jsonschema.Schema, bool) {
	required := false
	schema := jsonschema.NewArraySchema()
	schema.Items, _ = m.schemaForElement(item, rules.GetItems())

	if rules != nil {
		if rules.MaxItems != nil {
			schema.MaxItems = jsonschema.Size(rules.GetMaxItems())
		}

		if rules.MinItems != nil {
			schema.MinItems = jsonschema.Size(rules.GetMinItems())
			required = !rules.GetIgnoreEmpty()
		}

		if rules.Unique != nil {
			schema.UniqueItems = rules.GetUnique()
		}
	}

	return schema, required
}

func (m *Module) schemaForElement(element pgs.FieldTypeElem, rules *validate.FieldRules) (jsonschema.Schema, bool) {
	if element.IsEmbed() {
		return m.schemaForEmbed(element.Embed(), rules)
	}

	if element.IsEnum() {
		return m.schemaForEnum(element.Enum(), rules.GetEnum())
	}

	return m.schemaForScalar(element.ProtoType(), rules)
}
