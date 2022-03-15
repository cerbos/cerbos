// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import "encoding/json"

type Number json.RawMessage

func (n Number) IsNegative() bool {
	return len(n) > 1 && n[0] == '-'
}

func (n Number) IsPositive() bool {
	return !n.IsNegative() && !n.IsZero()
}

func (n Number) IsZero() bool {
	return len(n) == 1 && n[0] == '0'
}

func (n Number) MarshalJSON() ([]byte, error) {
	return json.RawMessage(n).MarshalJSON()
}

func (n *Number) UnmarshalJSON(data []byte) error {
	return (*json.RawMessage)(n).UnmarshalJSON(data)
}

type NumberSchema struct {
	GenericSchema
	Const            Number   `json:"const,omitempty"`
	Enum             []Number `json:"enum,omitempty"`
	Maximum          Number   `json:"maximum,omitempty"`
	ExclusiveMaximum Number   `json:"exclusiveMaximum,omitempty"`
	Minimum          Number   `json:"minimum,omitempty"`
	ExclusiveMinimum Number   `json:"exclusiveMinimum,omitempty"`
}

func NewIntegerSchema() *NumberSchema {
	return &NumberSchema{GenericSchema: GenericSchema{Type: "integer"}}
}

func NewNumberSchema() *NumberSchema {
	return &NumberSchema{GenericSchema: GenericSchema{Type: "number"}}
}
