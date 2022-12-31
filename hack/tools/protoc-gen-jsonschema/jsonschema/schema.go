// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

var (
	True  Schema = TrivialSchema(true)
	False Schema = TrivialSchema(false)
)

type Schema interface {
	implementsSchema()
}

type NonTrivialSchema interface {
	Schema
	Define(definitions map[string]Schema)
	TopLevel(id string)
}

type TrivialSchema bool

func (s TrivialSchema) MarshalJSON() ([]byte, error) {
	if s {
		return []byte("true"), nil
	}

	return []byte("false"), nil
}

func (TrivialSchema) implementsSchema() {}
