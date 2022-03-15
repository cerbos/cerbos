// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

type ArraySchema struct {
	GenericSchema
	Items       Schema  `json:"items,omitempty"`
	MaxItems    *uint64 `json:"maxItems,omitempty"`
	MinItems    *uint64 `json:"minItems,omitempty"`
	UniqueItems bool    `json:"uniqueItems,omitempty"`
}

func NewArraySchema() *ArraySchema {
	return &ArraySchema{GenericSchema: GenericSchema{Type: "array"}}
}
