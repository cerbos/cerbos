// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"encoding/json"

	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/jsonschema"
	"github.com/envoyproxy/protoc-gen-validate/validate"
	pgs "github.com/lyft/protoc-gen-star"
	"google.golang.org/protobuf/proto"
)

const (
	signedDecimalString   = `^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`
	unsignedDecimalString = `^(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`
)

type numericRules struct {
	Const       jsonschema.Number   `json:"const,omitempty"`
	Lt          jsonschema.Number   `json:"lt,omitempty"`
	Lte         jsonschema.Number   `json:"lte,omitempty"`
	Gt          jsonschema.Number   `json:"gt,omitempty"`
	Gte         jsonschema.Number   `json:"gte,omitempty"`
	In          []jsonschema.Number `json:"in,omitempty"`
	NotIn       []jsonschema.Number `json:"not_in,omitempty"`
	IgnoreEmpty bool                `json:"ignore_empty,omitempty"`
}

func (m *Module) schemaForNumericScalar(numeric pgs.ProtoType, fieldRules *validate.FieldRules) (jsonschema.Schema, bool) {
	required := false
	value := m.valueSchemaForNumericScalar(numeric)
	schemas := []jsonschema.NonTrivialSchema{m.stringValueSchemaForNumericScalar(numeric, value)}
	rules := m.numericRules(numeric, fieldRules)

	if rules != nil {
		if rules.Const != nil {
			value.Const = rules.Const
			required = !rules.IgnoreEmpty
		}

		if rules.Gt != nil {
			value.ExclusiveMinimum = rules.Gt
			if !rules.Gt.IsNegative() {
				required = !rules.IgnoreEmpty
			}
		}

		if rules.Gte != nil {
			value.Minimum = rules.Gte
			if rules.Gte.IsPositive() {
				required = !rules.IgnoreEmpty
			}
		}

		if len(rules.In) > 0 {
			value.Enum = rules.In
			required = !rules.IgnoreEmpty
		}

		if rules.Lt != nil {
			value.ExclusiveMaximum = rules.Lt
			if !rules.Lt.IsPositive() {
				required = !rules.IgnoreEmpty
			}
		}

		if rules.Lte != nil {
			value.Maximum = rules.Lte
			if rules.Lte.IsNegative() {
				required = !rules.IgnoreEmpty
			}
		}

		if len(rules.NotIn) > 0 {
			in := jsonschema.NewNumberSchema()
			in.Enum = rules.NotIn

			schemas = append(schemas, jsonschema.Not(in))
		}
	}

	return jsonschema.AllOf(schemas...), required
}

func (m *Module) valueSchemaForNumericScalar(numeric pgs.ProtoType) *jsonschema.NumberSchema {
	switch numeric {
	case pgs.Fixed32T, pgs.UInt32T, pgs.Fixed64T, pgs.UInt64T:
		schema := jsonschema.NewIntegerSchema()
		schema.Minimum = jsonschema.Number("0")
		return schema

	case pgs.Int32T, pgs.SFixed32, pgs.SInt32, pgs.Int64T, pgs.SFixed64, pgs.SInt64:
		return jsonschema.NewIntegerSchema()

	case pgs.DoubleT, pgs.FloatT:
		return jsonschema.NewNumberSchema()

	default:
		m.Failf("unknown numeric scalar type %q", numeric)
		return nil
	}
}

func (m *Module) stringValueSchemaForNumericScalar(numeric pgs.ProtoType, value *jsonschema.NumberSchema) jsonschema.NonTrivialSchema {
	var pattern string

	switch numeric {
	case pgs.Fixed64T, pgs.UInt64T:
		pattern = unsignedDecimalString

	case pgs.Int64T, pgs.SFixed64, pgs.SInt64:
		pattern = signedDecimalString

	default:
		return value
	}

	stringValue := jsonschema.NewStringSchema()
	stringValue.Pattern = pattern

	return jsonschema.OneOf(value, stringValue)
}

func (m *Module) numericRules(numeric pgs.ProtoType, fieldRules *validate.FieldRules) *numericRules {
	var source proto.Message

	switch numeric {
	case pgs.DoubleT:
		source = fieldRules.GetDouble()

	case pgs.Fixed32T:
		source = fieldRules.GetFixed32()

	case pgs.Fixed64T:
		source = fieldRules.GetFixed64()

	case pgs.FloatT:
		source = fieldRules.GetFloat()

	case pgs.Int32T:
		source = fieldRules.GetInt32()

	case pgs.Int64T:
		source = fieldRules.GetInt64()

	case pgs.SFixed32:
		source = fieldRules.GetSfixed32()

	case pgs.SFixed64:
		source = fieldRules.GetSfixed64()

	case pgs.SInt32:
		source = fieldRules.GetSint32()

	case pgs.SInt64:
		source = fieldRules.GetSint64()

	case pgs.StringT:
		source = fieldRules.GetString_()

	case pgs.UInt32T:
		source = fieldRules.GetUint32()

	case pgs.UInt64T:
		source = fieldRules.GetUint64()

	default:
		m.Failf("unknown numeric scalar type %q", numeric)
		return nil
	}

	if source == nil {
		return nil
	}

	data, err := json.Marshal(source)
	m.CheckErr(err, "failed to marshal numeric validation rules to JSON")

	target := &numericRules{}
	err = json.Unmarshal(data, target)
	m.CheckErr(err, "failed to unmarshal numeric validation rules from JSON")

	return target
}
