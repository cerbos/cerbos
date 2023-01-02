// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

type StringFormat string

const (
	StringFormatDateTime     StringFormat = "date-time"
	StringFormatEmail        StringFormat = "email"
	StringFormatHostname     StringFormat = "hostname"
	StringFormatIPv4         StringFormat = "ipv4"
	StringFormatIPv6         StringFormat = "ipv6"
	StringFormatURI          StringFormat = "uri"
	StringFormatURIReference StringFormat = "uri-reference"
)

type StringSchema struct {
	GenericSchema
	Const     *string      `json:"const,omitempty"`
	Enum      []string     `json:"enum,omitempty"`
	MaxLength *uint64      `json:"maxLength,omitempty"`
	MinLength *uint64      `json:"minLength,omitempty"`
	Pattern   string       `json:"pattern,omitempty"`
	Format    StringFormat `json:"format,omitempty"`
}

func NewStringSchema() *StringSchema {
	return &StringSchema{GenericSchema: GenericSchema{Type: "string"}}
}
