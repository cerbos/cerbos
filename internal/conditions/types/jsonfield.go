// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/cel-go/common/types"
	"github.com/iancoleman/strcase"
)

// JSONFieldProvider is a custom type provider that allows protobuf fields to be accessed by their JSON name (camel case).
type JSONFieldProvider struct {
	types.Provider
}

func NewCamelCaseFieldProvider(tp types.Provider) *JSONFieldProvider {
	return &JSONFieldProvider{Provider: tp}
}

func (ccfp *JSONFieldProvider) FindStructFieldType(msgType, fieldName string) (*types.FieldType, bool) {
	if ft, ok := ccfp.Provider.FindStructFieldType(msgType, fieldName); ok {
		return ft, ok
	}

	sc := strcase.ToSnake(fieldName)
	return ccfp.Provider.FindStructFieldType(msgType, sc)
}
