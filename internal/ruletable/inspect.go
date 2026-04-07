// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

import (
	"cmp"
	"fmt"
	"slices"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"google.golang.org/protobuf/types/known/structpb"
)

// ListRuleTableRowActions returns unique list of actions in a rule table row.
func ListRuleTableRowActions(b *index.Binding) []string {
	if b == nil {
		return nil
	}

	var actions []string

	if b.Action != "" {
		actions = append(actions, b.Action)
	}
	for action := range b.AllowActions {
		actions = append(actions, action)
	}

	if len(actions) > 1 {
		slices.Sort(actions)
	}

	return actions
}

// ListRuleTableRowConstants returns local and exported constants defined in a binding.
func ListRuleTableRowConstants(b *index.Binding) ([]*responsev1.InspectPoliciesResponse_Constant, error) {
	if b == nil {
		return nil, nil
	}

	var nParams, nDRParams int
	if b.Core.Params != nil {
		nParams = len(b.Core.Params.Constants)
	}
	if b.Core.DerivedRoleParams != nil {
		nDRParams = len(b.Core.DerivedRoleParams.Constants)
	}

	constants := make([]*responsev1.InspectPoliciesResponse_Constant, 0, nParams+nDRParams)
	if b.Core.Params != nil {
		for name, value := range b.Core.Params.Constants {
			pbVal, err := structpb.NewValue(value)
			if err != nil {
				return nil, fmt.Errorf("converting constant %q: %w", name, err)
			}
			constants = append(constants, &responsev1.InspectPoliciesResponse_Constant{
				Name:  name,
				Value: pbVal,
				Kind:  responsev1.InspectPoliciesResponse_Constant_KIND_UNKNOWN,
			})
		}
	}
	if b.Core.DerivedRoleParams != nil {
		for name, value := range b.Core.DerivedRoleParams.Constants {
			pbVal, err := structpb.NewValue(value)
			if err != nil {
				return nil, fmt.Errorf("converting derived role constant %q: %w", name, err)
			}
			constants = append(constants, &responsev1.InspectPoliciesResponse_Constant{
				Name:  name,
				Value: pbVal,
				Kind:  responsev1.InspectPoliciesResponse_Constant_KIND_UNKNOWN,
			})
		}
	}

	if len(constants) > 1 {
		slices.SortFunc(constants, func(a, b *responsev1.InspectPoliciesResponse_Constant) int {
			if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
				return kind
			}

			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return constants, nil
}

// GetRuleTableRowDerivedRoles returns the derived role defined in a binding if it exists.
func GetRuleTableRowDerivedRoles(b *index.Binding) *responsev1.InspectPoliciesResponse_DerivedRole {
	if b == nil || b.OriginDerivedRole == "" {
		return nil
	}

	return &responsev1.InspectPoliciesResponse_DerivedRole{
		Name: b.OriginDerivedRole,
		Kind: responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED,
	}
}

// ListRuleTableRowVariables returns local and exported variables defined in a binding.
func ListRuleTableRowVariables(b *index.Binding) []*responsev1.InspectPoliciesResponse_Variable {
	if b == nil || b.Core.Params == nil {
		return nil
	}

	variables := make([]*responsev1.InspectPoliciesResponse_Variable, len(b.Core.Params.Variables))
	for i, v := range b.Core.Params.Variables {
		variables[i] = &responsev1.InspectPoliciesResponse_Variable{
			Name:  v.Name,
			Value: v.Expr.Original,
			Kind:  responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN,
		}
	}

	if len(variables) > 1 {
		slices.SortFunc(variables, func(a, b *responsev1.InspectPoliciesResponse_Variable) int {
			if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
				return kind
			}

			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return variables
}
