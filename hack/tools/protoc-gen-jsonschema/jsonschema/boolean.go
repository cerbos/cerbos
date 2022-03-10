// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build protocgenjsonschema
// +build protocgenjsonschema

package jsonschema

type BooleanSchema struct {
	GenericSchema
	Const *bool `json:"const,omitempty"`
}

func NewBooleanSchema() *BooleanSchema {
	return &BooleanSchema{GenericSchema: GenericSchema{Type: "boolean"}}
}
