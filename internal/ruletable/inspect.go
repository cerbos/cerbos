// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

import (
	"cmp"
	"slices"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/util"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/ruletable/index"
)

// ListRuleTableRowActions returns unique list of actions in a rule table row.
func ListRuleTableRowActions(row *index.Row) []string {
	var actions []string
	if row == nil {
		return actions
	}

	ss := make(util.StringSet)

	switch a := row.GetActionSet().(type) {
	case *runtimev1.RuleTable_RuleRow_Action:
		if !ss.Contains(a.Action) {
			actions = append(actions, a.Action)
		}

	case *runtimev1.RuleTable_RuleRow_AllowActions_:
		for action := range a.AllowActions.Actions {
			if !ss.Contains(action) {
				actions = append(actions, action)
			}
		}
	}

	if len(actions) > 1 {
		slices.Sort(actions)
	}

	return actions
}

// ListRuleTableRowConstants returns local and exported constants defined in a rule table row.
func ListRuleTableRowConstants(row *index.Row) []*responsev1.InspectPoliciesResponse_Constant {
	if row == nil {
		return nil
	}

	constants := make([]*responsev1.InspectPoliciesResponse_Constant, len(row.GetParams().GetConstants())+len(row.GetDerivedRoleParams().GetConstants()))
	i := 0
	for name, value := range row.GetParams().GetConstants() {
		constants[i] = &responsev1.InspectPoliciesResponse_Constant{
			Name:  name,
			Value: value,
			Kind:  responsev1.InspectPoliciesResponse_Constant_KIND_UNKNOWN,
		}

		i++
	}

	for name, value := range row.GetDerivedRoleParams().GetConstants() {
		constants[i] = &responsev1.InspectPoliciesResponse_Constant{
			Name:  name,
			Value: value,
			Kind:  responsev1.InspectPoliciesResponse_Constant_KIND_UNKNOWN,
		}

		i++
	}

	if len(constants) > 1 {
		slices.SortFunc(constants, func(a, b *responsev1.InspectPoliciesResponse_Constant) int {
			if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
				return kind
			}

			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return constants
}

// GetRuleTableRowDerivedRoles returns the derived role defined in a rule table row if it exists.
func GetRuleTableRowDerivedRoles(row *index.Row) *responsev1.InspectPoliciesResponse_DerivedRole {
	if row == nil || row.GetOriginDerivedRole() == "" {
		return nil
	}

	return &responsev1.InspectPoliciesResponse_DerivedRole{
		Name: row.GetOriginDerivedRole(),
		Kind: responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED,
	}
}

// ListRuleTableRowVariables returns local and exported variables defined in a rule table row.
func ListRuleTableRowVariables(row *index.Row) []*responsev1.InspectPoliciesResponse_Variable {
	if row == nil {
		return nil
	}

	variables := make([]*responsev1.InspectPoliciesResponse_Variable, len(row.GetParams().GetOrderedVariables()))
	for i := 0; i < len(row.GetParams().GetOrderedVariables()); i++ {
		variable := row.GetParams().GetOrderedVariables()[i]
		variables[i] = &responsev1.InspectPoliciesResponse_Variable{
			Name:  variable.Name,
			Value: variable.Expr.Original,
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
