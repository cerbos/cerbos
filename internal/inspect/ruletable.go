// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/util"
)

func RuleTables(ruleTable *ruletable.RuleTable) *RuleTable {
	return &RuleTable{
		ruleTable: ruleTable,
		results:   make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}
}

type RuleTable struct {
	ruleTable *ruletable.RuleTable
	results   map[string]*responsev1.InspectPoliciesResponse_Result
}

// Inspect inspects the given rule table and caches the inspection related information internally.
func (rt *RuleTable) Inspect(ctx context.Context) error {
	if rt.ruleTable == nil {
		return fmt.Errorf("rule table is nil")
	}

	rows, err := rt.ruleTable.GetAllRows(ctx)
	if err != nil {
		return fmt.Errorf("failed to get all rows from rule table: %w", err)
	}

	results := make(map[string]*responsev1.InspectPoliciesResponse_Result)
	actionSets := make(map[string]util.StringSet)
	attrSets := make(map[string]util.StringSet)
	constantSets := make(map[string]util.StringSet)
	derivedRoleSets := make(map[string]util.StringSet)
	variableSets := make(map[string]util.StringSet)
	for _, row := range rows {
		policyKey := namer.PolicyKeyFromFQN(row.OriginFqn)

		var result *responsev1.InspectPoliciesResponse_Result
		if existingResult, ok := results[policyKey]; ok {
			result = existingResult
		} else {
			result = &responsev1.InspectPoliciesResponse_Result{
				PolicyId: namer.PolicyKeyFromFQN(policyKey),
			}
		}
		results[policyKey] = result

		var actionSet util.StringSet
		if existingActionSet, ok := actionSets[policyKey]; ok {
			actionSet = existingActionSet
		} else {
			actionSet = make(util.StringSet)
		}
		actionSets[policyKey] = actionSet

		var attrSet util.StringSet
		if existingAttrSet, ok := attrSets[policyKey]; ok {
			attrSet = existingAttrSet
		} else {
			attrSet = make(util.StringSet)
		}
		attrSets[policyKey] = attrSet

		var constantSet util.StringSet
		if existingConstantSet, ok := constantSets[policyKey]; ok {
			constantSet = existingConstantSet
		} else {
			constantSet = make(util.StringSet)
		}
		constantSets[policyKey] = constantSet

		var derivedRoleSet util.StringSet
		if existingDerivedRoleSet, ok := derivedRoleSets[policyKey]; ok {
			derivedRoleSet = existingDerivedRoleSet
		} else {
			derivedRoleSet = make(util.StringSet)
		}
		derivedRoleSets[policyKey] = derivedRoleSet

		var variableSet util.StringSet
		if existingVariableSet, ok := variableSets[policyKey]; ok {
			variableSet = existingVariableSet
		} else {
			variableSet = make(util.StringSet)
		}
		variableSets[policyKey] = variableSet

		if err := rt.inspectRow(row, actionSet, attrSet, constantSet, derivedRoleSet, variableSet, result); err != nil {
			return err
		}
	}

	rt.results = results
	return nil
}

func (rt *RuleTable) inspectRow(
	row *index.Row,
	actionSet util.StringSet,
	attrSet util.StringSet,
	constantSet util.StringSet,
	derivedRoleSet util.StringSet,
	variableSet util.StringSet,
	result *responsev1.InspectPoliciesResponse_Result,
) error {
	for _, action := range ruletable.ListRuleTableRowActions(row) {
		if !actionSet.Contains(action) {
			actionSet[action] = struct{}{}
			result.Actions = append(result.GetActions(), action)
		}
	}

	attrs := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	if err := visitRuleTableRow(row, attributeVisitor(attrs)); err != nil {
		return err
	}
	for key, attr := range attrs {
		if !attrSet.Contains(key) {
			attrSet[key] = struct{}{}
			result.Attributes = append(result.GetAttributes(), attr)
		}
	}

	for _, constant := range ruletable.ListRuleTableRowConstants(row) {
		if !constantSet.Contains(constant.Name) {
			constantSet[constant.Name] = struct{}{}
			result.Constants = append(result.GetConstants(), constant)
		}
	}

	if derivedRole := ruletable.GetRuleTableRowDerivedRoles(row); derivedRole != nil {
		if !derivedRoleSet.Contains(derivedRole.Name) {
			derivedRoleSet[derivedRole.Name] = struct{}{}
			result.DerivedRoles = append(result.GetDerivedRoles(), derivedRole)
		}
	}

	for _, variable := range ruletable.ListRuleTableRowVariables(row) {
		if !variableSet.Contains(variable.Name) {
			variableSet[variable.Name] = struct{}{}
			result.Variables = append(result.GetVariables(), variable)
		}
	}

	return nil
}

// Results returns the final inspection results.
func (rt *RuleTable) Results() map[string]*responsev1.InspectPoliciesResponse_Result {
	for _, result := range rt.results {
		if len(result.GetActions()) > 1 {
			slices.Sort(result.GetActions())
		}

		if len(result.GetAttributes()) > 1 {
			slices.SortFunc(result.GetAttributes(), func(a, b *responsev1.InspectPoliciesResponse_Attribute) int {
				if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
					return kind
				}

				return cmp.Compare(a.GetName(), b.GetName())
			})
		}

		if len(result.GetConstants()) > 1 {
			slices.SortFunc(result.GetConstants(), func(a, b *responsev1.InspectPoliciesResponse_Constant) int {
				if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
					return kind
				}

				return cmp.Compare(a.GetName(), b.GetName())
			})
		}

		if len(result.GetDerivedRoles()) > 1 {
			slices.SortFunc(result.GetDerivedRoles(), func(a, b *responsev1.InspectPoliciesResponse_DerivedRole) int {
				if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
					return kind
				}

				return cmp.Compare(a.GetName(), b.GetName())
			})
		}

		if len(result.GetVariables()) > 1 {
			slices.SortFunc(result.GetVariables(), func(a, b *responsev1.InspectPoliciesResponse_Variable) int {
				if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
					return kind
				}

				return cmp.Compare(a.GetName(), b.GetName())
			})
		}
	}

	return rt.results
}
