// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

type ObjectSchema struct {
	GenericSchema
	MaxProperties        *uint64           `json:"maxProperties,omitempty"`
	MinProperties        *uint64           `json:"minProperties,omitempty"`
	Required             []string          `json:"required,omitempty"`
	AdditionalProperties Schema            `json:"additionalProperties,omitempty"`
	Properties           map[string]Schema `json:"properties,omitempty"`
	PropertyNames        Schema            `json:"propertyNames,omitempty"`
}

func NewObjectSchema() *ObjectSchema {
	return &ObjectSchema{
		GenericSchema: GenericSchema{Type: "object"},
		Properties:    make(map[string]Schema),
	}
}
