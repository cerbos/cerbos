// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"

	"github.com/google/cel-go/common/types"
)

const variablesTypeName = "cerbos.Variables"

var VariablesType = types.NewObjectType(variablesTypeName)

type Variables interface {
	IsSet(name string) bool
	Get(name string) (any, error)
}

type VariablesMap map[string]any

var _ Variables = (VariablesMap)(nil)

func (m VariablesMap) IsSet(name string) bool {
	_, ok := m[name]
	return ok
}

func (m VariablesMap) Get(name string) (any, error) {
	value, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("undefined field '%s'", name)
	}

	return value, nil
}

func variablesFieldType(fieldName string) (*types.FieldType, bool) {
	return &types.FieldType{
		Type: types.DynType,
		IsSet: func(target any) bool {
			variables, ok := target.(Variables)
			return ok && variables.IsSet(fieldName)
		},
		GetFrom: func(target any) (any, error) {
			variables, ok := target.(Variables)
			if !ok {
				return nil, fmt.Errorf("failed to get field '%s' from target %T", fieldName, target)
			}

			return variables.Get(fieldName)
		},
	}, true
}
