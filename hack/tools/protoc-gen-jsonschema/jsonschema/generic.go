// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

type GenericSchema struct {
	ID          string             `json:"$id,omitempty"`
	Version     string             `json:"$schema,omitempty"`
	Ref         string             `json:"$ref,omitempty"`
	Definitions map[string]Schema  `json:"definitions,omitempty"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description,omitempty"`
	Type        string             `json:"type,omitempty"`
	AllOf       []NonTrivialSchema `json:"allOf,omitempty"`
	AnyOf       []NonTrivialSchema `json:"anyOf,omitempty"`
	OneOf       []NonTrivialSchema `json:"oneOf,omitempty"`
	Not         Schema             `json:"not,omitempty"`
}

func Ref(ref string) *GenericSchema {
	return &GenericSchema{Ref: ref}
}

func AllOf(schemas ...NonTrivialSchema) NonTrivialSchema {
	if len(schemas) == 1 {
		return schemas[0]
	}

	return &GenericSchema{AllOf: schemas}
}

func AnyOf(schemas ...NonTrivialSchema) NonTrivialSchema {
	if len(schemas) == 1 {
		return schemas[0]
	}

	return &GenericSchema{AnyOf: schemas}
}

func OneOf(schemas ...NonTrivialSchema) NonTrivialSchema {
	if len(schemas) == 1 {
		return schemas[0]
	}

	return &GenericSchema{OneOf: schemas}
}

func Not(schema Schema) *GenericSchema {
	return &GenericSchema{Not: schema}
}

func (s *GenericSchema) Define(definitions map[string]Schema) {
	s.Definitions = definitions
}

func (s *GenericSchema) TopLevel(id string) {
	s.ID = id
	s.Version = "http://json-schema.org/draft-07/schema#"
}

func (*GenericSchema) implementsSchema() {}
