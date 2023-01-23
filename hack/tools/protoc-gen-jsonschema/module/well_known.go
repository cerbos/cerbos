// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"encoding/json"
	"fmt"

	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/jsonschema"
	"github.com/envoyproxy/protoc-gen-validate/validate"
	pgs "github.com/lyft/protoc-gen-star/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	duration "google.golang.org/protobuf/types/known/durationpb"
)

type wellKnownType pgs.WellKnownType

const (
	wellKnownTypeAny       = wellKnownType(pgs.AnyWKT)
	wellKnownTypeDuration  = wellKnownType(pgs.DurationWKT)
	wellKnownTypeEmpty     = wellKnownType(pgs.EmptyWKT)
	wellKnownTypeListValue = wellKnownType(pgs.ListValueWKT)
	wellKnownTypeStruct    = wellKnownType(pgs.StructWKT)
	wellKnownTypeTimestamp = wellKnownType(pgs.TimestampWKT)
	wellKnownTypeValue     = wellKnownType(pgs.ValueWKT)
)

func (t wellKnownType) FullyQualifiedName() string {
	return fmt.Sprintf(".%s.%s", pgs.WellKnownTypePackage, t)
}

func (m *Module) defineAny() jsonschema.Schema {
	typeURL := jsonschema.NewStringSchema()
	typeURL.Title = "Type URL"
	typeURL.Description = "A URL/resource name whose content describes the type of the serialized message."
	typeURL.Format = jsonschema.StringFormatURIReference

	schema := jsonschema.NewObjectSchema()
	schema.Title = "Any"
	schema.Description = "An arbitrary serialized message, along with a URL that describes the type of the serialized message."
	schema.Properties["@type"] = typeURL
	schema.AdditionalProperties = jsonschema.True
	return schema
}

func (m *Module) defineDuration() jsonschema.Schema {
	schema := jsonschema.NewStringSchema()
	schema.Title = "Duration"
	schema.Description = "A signed, fixed-length span of time represented as a count of seconds and fractions of seconds at nanosecond resolution."
	schema.Pattern = `^-?(?:0|[1-9]\d*)(?:\.\d+)?s$`
	return schema
}

func (m *Module) defineEmpty() jsonschema.Schema {
	schema := jsonschema.NewObjectSchema()
	schema.Title = "Empty"
	schema.Description = "A generic empty message."
	schema.AdditionalProperties = jsonschema.False
	return schema
}

func (m *Module) defineListValue() jsonschema.Schema {
	schema := jsonschema.NewArraySchema()
	schema.Title = "ListValue"
	schema.Description = "A repeated field of dynamically-typed values."
	schema.Items = m.ref(wellKnownTypeValue, m.defineValue)
	return schema
}

func (m *Module) defineStruct() jsonschema.Schema {
	schema := jsonschema.NewObjectSchema()
	schema.Title = "Struct"
	schema.Description = "A structured data value, consisting of fields which map to dynamically-typed values."
	schema.AdditionalProperties = m.ref(wellKnownTypeValue, m.defineValue)
	return schema
}

func (m *Module) defineTimestamp() jsonschema.Schema {
	schema := jsonschema.NewStringSchema()
	schema.Title = "Timestamp"
	schema.Description = "A point in time, independent of any time zone or calendar."
	schema.Format = jsonschema.StringFormatDateTime
	return schema
}

func (m *Module) defineValue() jsonschema.Schema {
	return &jsonschema.GenericSchema{
		Title:       "Value",
		Description: "A dynamically-typed value.",
	}
}

func (m *Module) schemaForWellKnownType(name pgs.WellKnownType, rules *validate.FieldRules) (jsonschema.Schema, bool) {
	switch name {
	case pgs.AnyWKT:
		return m.schemaForAny(rules.GetAny())

	case pgs.BoolValueWKT:
		return m.schemaForBool(rules.GetBool())

	case pgs.BytesValueWKT:
		return m.schemaForBytes(rules.GetBytes())

	case pgs.DoubleValueWKT:
		return m.schemaForNumericScalar(pgs.DoubleT, rules)

	case pgs.DurationWKT:
		return m.schemaForDuration(rules.GetDuration())

	case pgs.EmptyWKT:
		return m.ref(wellKnownTypeEmpty, m.defineEmpty), false

	case pgs.FloatValueWKT:
		return m.schemaForNumericScalar(pgs.FloatT, rules)

	case pgs.Int32ValueWKT:
		return m.schemaForNumericScalar(pgs.Int32T, rules)

	case pgs.Int64ValueWKT:
		return m.schemaForNumericScalar(pgs.Int64T, rules)

	case pgs.ListValueWKT:
		return m.ref(wellKnownTypeListValue, m.defineListValue), false

	case pgs.StringValueWKT:
		return m.schemaForString(rules.GetString_())

	case pgs.StructWKT:
		return m.ref(wellKnownTypeStruct, m.defineStruct), false

	case pgs.TimestampWKT:
		return m.schemaForTimestamp(rules.GetTimestamp())

	case pgs.UInt32ValueWKT:
		return m.schemaForNumericScalar(pgs.UInt32T, rules)

	case pgs.UInt64ValueWKT:
		return m.schemaForNumericScalar(pgs.UInt64T, rules)

	case pgs.ValueWKT:
		return m.ref(wellKnownTypeValue, m.defineValue), false

	default:
		m.Failf("unexpected well-known type %q", name)
		return nil, false
	}
}

func (m *Module) schemaForAny(rules *validate.AnyRules) (jsonschema.Schema, bool) {
	schemas := []jsonschema.NonTrivialSchema{m.ref(wellKnownTypeAny, m.defineAny)}

	if rules != nil {
		if len(rules.In) > 0 {
			schemas = append(schemas, m.schemaForAnyIn(rules.In))
		}

		if len(rules.NotIn) > 0 {
			schemas = append(schemas, jsonschema.Not(m.schemaForAnyIn(rules.NotIn)))
		}
	}

	return jsonschema.AllOf(schemas...), rules.GetRequired()
}

func (m *Module) schemaForAnyIn(typeURLs []string) *jsonschema.ObjectSchema {
	typeURL := jsonschema.NewStringSchema()
	typeURL.Enum = typeURLs

	schema := jsonschema.NewObjectSchema()
	schema.Properties["@type"] = typeURL
	return schema
}

func (m *Module) schemaForDuration(rules *validate.DurationRules) (jsonschema.Schema, bool) {
	schemas := []jsonschema.NonTrivialSchema{m.ref(wellKnownTypeDuration, m.defineDuration)}

	if rules != nil {
		if rules.Const != nil {
			schemas = append(schemas, m.schemaForProtoJSONStringConst(rules.Const))
		}

		if len(rules.In) > 0 {
			schemas = append(schemas, m.schemaForDurationIn(rules.In))
		}

		if len(rules.NotIn) > 0 {
			schemas = append(schemas, jsonschema.Not(m.schemaForDurationIn(rules.In)))
		}
	}

	return jsonschema.AllOf(schemas...), rules.GetRequired()
}

func (m *Module) schemaForDurationIn(durations []*duration.Duration) *jsonschema.StringSchema {
	schema := jsonschema.NewStringSchema()
	for _, duration := range durations {
		schema.Enum = append(schema.Enum, m.protoJSONString(duration))
	}
	return schema
}

func (m *Module) schemaForTimestamp(rules *validate.TimestampRules) (jsonschema.Schema, bool) {
	schemas := []jsonschema.NonTrivialSchema{m.ref(wellKnownTypeTimestamp, m.defineTimestamp)}

	if rules != nil {
		if rules.Const != nil {
			schemas = append(schemas, m.schemaForProtoJSONStringConst(rules.Const))
		}
	}

	return jsonschema.AllOf(schemas...), rules.GetRequired()
}

func (m *Module) schemaForProtoJSONStringConst(value proto.Message) *jsonschema.StringSchema {
	schema := jsonschema.NewStringSchema()
	schema.Const = jsonschema.String(m.protoJSONString(value))
	return schema
}

func (m *Module) protoJSONString(value proto.Message) string {
	data, err := protojson.Marshal(value)
	m.CheckErr(err, "failed to marshal value to proto JSON")

	var result string
	err = json.Unmarshal(data, &result)
	m.CheckErr(err, "failed to unmarshal value from proto JSON")

	return result
}
