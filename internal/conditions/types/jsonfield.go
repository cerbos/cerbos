// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/cel-go/common/types/ref"
	"github.com/iancoleman/strcase"
)

// JSONFieldProvider is a custom type provider that allows protobuf fields to be accessed by their JSON name (camel case).
type JSONFieldProvider struct {
	ref.TypeProvider
}

func NewCamelCaseFieldProvider(tp ref.TypeProvider) *JSONFieldProvider {
	return &JSONFieldProvider{TypeProvider: tp}
}

func (ccfp *JSONFieldProvider) FindFieldType(msgType, fieldName string) (*ref.FieldType, bool) {
	if ft, ok := ccfp.TypeProvider.FindFieldType(msgType, fieldName); ok {
		return ft, ok
	}

	sc := strcase.ToSnake(fieldName)
	return ccfp.TypeProvider.FindFieldType(msgType, sc)
}
