// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/iancoleman/strcase"
)

// jsonFieldProvider is a custom type provider that allows protobuf fields to be accessed by their JSON name (camel case).
type jsonFieldProvider struct {
	types.Provider
}

func JSONFields() cel.EnvOption {
	return func(env *cel.Env) (*cel.Env, error) {
		return cel.CustomTypeProvider(&jsonFieldProvider{Provider: env.CELTypeProvider()})(env)
	}
}

func (p *jsonFieldProvider) FindStructFieldType(msgType, fieldName string) (*types.FieldType, bool) {
	if ft, ok := p.Provider.FindStructFieldType(msgType, fieldName); ok {
		return ft, ok
	}

	return p.Provider.FindStructFieldType(msgType, strcase.ToSnake(fieldName))
}
