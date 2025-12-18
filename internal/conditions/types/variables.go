// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

const variablesTypeName = "cerbos.Variables"

var VariablesType = types.NewObjectType(variablesTypeName)

type variablesProvider struct {
	types.Provider
}

var _ types.Provider = (*variablesProvider)(nil)

func Variables() cel.EnvOption {
	return func(env *cel.Env) (*cel.Env, error) {
		return cel.CustomTypeProvider(&variablesProvider{Provider: env.CELTypeProvider()})(env)
	}
}

func (p *variablesProvider) FindStructType(structType string) (*types.Type, bool) {
	if structType == variablesTypeName {
		return VariablesType, true
	}

	return p.Provider.FindStructType(structType)
}

func (p *variablesProvider) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	if structType == variablesTypeName {
		return &types.FieldType{
			Type: types.DynType,
			IsSet: func(target any) bool {
				if m, ok := target.(map[string]any); ok {
					_, ok := m[fieldName]
					return ok
				}
				return false
			},
			GetFrom: func(target any) (any, error) {
				m, ok := target.(map[string]any)
				if ok {
					return m[fieldName], nil
				}

				return nil, fmt.Errorf("failed to get field %q from target %T (expected %T)", fieldName, target, m)
			},
		}, true
	}

	return p.Provider.FindStructFieldType(structType, fieldName)
}
