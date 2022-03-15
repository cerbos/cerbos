// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"regexp"

	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/jsonschema"
	"github.com/envoyproxy/protoc-gen-validate/validate"
	pgs "github.com/lyft/protoc-gen-star"
)

func (m *Module) schemaForScalar(scalar pgs.ProtoType, rules *validate.FieldRules) (jsonschema.Schema, bool) {
	if scalar.IsNumeric() {
		return m.schemaForNumericScalar(scalar, rules)
	}

	switch scalar {
	case pgs.BoolT:
		return m.schemaForBool(rules.GetBool())

	case pgs.BytesT:
		return m.schemaForBytes(rules.GetBytes())

	case pgs.StringT:
		return m.schemaForString(rules.GetString_())

	default:
		m.Failf("unexpected scalar type %q", scalar)
		return nil, false
	}
}

func (m *Module) schemaForBool(rules *validate.BoolRules) (jsonschema.Schema, bool) {
	required := false
	schema := jsonschema.NewBooleanSchema()

	if rules != nil {
		if rules.Const != nil {
			schema.Const = jsonschema.Boolean(rules.GetConst())
			required = true
		}
	}

	return schema, required
}

func (m *Module) schemaForBytes(rules *validate.BytesRules) (jsonschema.Schema, bool) {
	required := false

	standard := jsonschema.NewStringSchema()
	standard.Title = "Standard base64 encoding"
	standard.Pattern = `^[\r\nA-Za-z0-9+/]*$`

	urlSafe := jsonschema.NewStringSchema()
	urlSafe.Title = "URL-safe base64 encoding"
	urlSafe.Pattern = `^[\r\nA-Za-z0-9_-]*$`

	schema := jsonschema.NewStringSchema()
	schema.OneOf = []jsonschema.NonTrivialSchema{standard, urlSafe}

	if rules != nil {
		required = !rules.GetIgnoreEmpty() &&
			(len(rules.Const) > 0 ||
				len(rules.Contains) > 0 ||
				len(rules.In) > 0 ||
				rules.MinLen != nil ||
				rules.Pattern != nil ||
				len(rules.Prefix) > 0 ||
				len(rules.Suffix) > 0 ||
				rules.WellKnown != nil)
	}

	return schema, required
}

func (m *Module) schemaForString(rules *validate.StringRules) (jsonschema.Schema, bool) {
	required := false
	schema := jsonschema.NewStringSchema()
	schemas := []jsonschema.NonTrivialSchema{schema}
	var patterns []string

	if rules != nil {
		if rules.Const != nil {
			schema.Const = jsonschema.String(rules.GetConst())
			required = !rules.GetIgnoreEmpty()
		}

		if rules.Contains != nil {
			patterns = append(patterns, regexp.QuoteMeta(rules.GetContains()))
			required = !rules.GetIgnoreEmpty()
		}

		if len(rules.In) > 0 {
			schema.Enum = rules.In
			required = !rules.GetIgnoreEmpty()
		}

		if rules.Len != nil {
			schema.MaxLength = jsonschema.Size(rules.GetLen())
			schema.MinLength = jsonschema.Size(rules.GetLen())
			required = !rules.GetIgnoreEmpty()
		}

		if rules.LenBytes != nil || rules.MinBytes != nil {
			required = !rules.GetIgnoreEmpty()
		}

		if rules.MaxLen != nil {
			schema.MaxLength = jsonschema.Size(rules.GetMaxLen())
		}

		if rules.MinLen != nil {
			schema.MinLength = jsonschema.Size(rules.GetMinLen())
			required = !rules.GetIgnoreEmpty()
		}

		if rules.NotContains != nil {
			contains := jsonschema.NewStringSchema()
			contains.Pattern = regexp.QuoteMeta(rules.GetNotContains())
			schemas = append(schemas, jsonschema.Not(contains))
		}

		if len(rules.NotIn) > 0 {
			in := jsonschema.NewStringSchema()
			in.Enum = rules.NotIn
			schemas = append(schemas, jsonschema.Not(in))
		}

		if rules.Pattern != nil {
			patterns = append(patterns, rules.GetPattern())
			if !m.matchesEmptyString(rules.GetPattern()) {
				required = !rules.GetIgnoreEmpty()
			}
		}

		if rules.Prefix != nil {
			patterns = append(patterns, "^"+regexp.QuoteMeta(rules.GetPrefix()))
			required = !rules.GetIgnoreEmpty()
		}

		if rules.Suffix != nil {
			patterns = append(patterns, regexp.QuoteMeta(rules.GetSuffix())+"$")
			required = !rules.GetIgnoreEmpty()
		}

		if rules.WellKnown != nil {
			switch rules.WellKnown.(type) {
			case *validate.StringRules_Address:
				schemas = append(schemas, m.schemaForStringFormats(jsonschema.StringFormatHostname, jsonschema.StringFormatIPv4, jsonschema.StringFormatIPv6))

			case *validate.StringRules_Email:
				schema.Format = jsonschema.StringFormatEmail

			case *validate.StringRules_Hostname:
				schema.Format = jsonschema.StringFormatHostname

			case *validate.StringRules_Ip:
				schemas = append(schemas, m.schemaForStringFormats(jsonschema.StringFormatIPv4, jsonschema.StringFormatIPv6))

			case *validate.StringRules_Ipv4:
				schema.Format = jsonschema.StringFormatIPv4

			case *validate.StringRules_Ipv6:
				schema.Format = jsonschema.StringFormatIPv6

			case *validate.StringRules_Uri:
				schema.Format = jsonschema.StringFormatURI

			case *validate.StringRules_UriRef:
				schema.Format = jsonschema.StringFormatURIReference
			}

			required = !rules.GetIgnoreEmpty()
		}
	}

	if len(patterns) == 1 {
		schema.Pattern = patterns[0]
	} else {
		for _, pattern := range patterns {
			match := jsonschema.NewStringSchema()
			match.Pattern = pattern
			schemas = append(schemas, match)
		}
	}

	return jsonschema.AllOf(schemas...), required
}

func (m *Module) schemaForStringFormats(formats ...jsonschema.StringFormat) jsonschema.NonTrivialSchema {
	schemas := make([]jsonschema.NonTrivialSchema, len(formats))

	for i, format := range formats {
		schema := jsonschema.NewStringSchema()
		schema.Format = format
		schemas[i] = schema
	}

	return jsonschema.AnyOf(schemas...)
}

func (m *Module) matchesEmptyString(pattern string) bool {
	match, err := regexp.MatchString(pattern, "")
	m.CheckErr(err, "failed to check if pattern matches empty string")
	return match
}
