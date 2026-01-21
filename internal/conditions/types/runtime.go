// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/google/cel-go/common/types"
)

var (
	RuntimeType     = MessageType[*enginev1.Runtime]()
	runtimeTypeName = RuntimeType.TypeName()
)

type Runtime interface {
	GetEffectiveDerivedRoles() []string
}

var _ Runtime = (*enginev1.Runtime)(nil)

func runtimeFieldType(fieldName string) (*types.FieldType, bool) {
	switch fieldName {
	case "effective_derived_roles", "effectiveDerivedRoles":
		return &types.FieldType{
			Type: types.NewListType(types.StringType),
			IsSet: func(target any) bool {
				_, ok := target.(Runtime)
				return ok
			},
			GetFrom: func(target any) (any, error) {
				runtime, ok := target.(Runtime)
				if !ok {
					return nil, fmt.Errorf("failed to get field '%s' from target %T", fieldName, target)
				}

				return runtime.GetEffectiveDerivedRoles(), nil
			},
		}, true

	default:
		return nil, false
	}
}
