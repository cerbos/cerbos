// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"cmp"
	"fmt"
	"slices"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// BindingSource provides access to index bindings for inspection.
// It exists here to prevent a circular dependency between `inspect`, `ruletable` and `storage`.
type BindingSource interface {
	GetAllRows() []*index.Binding
}

func RuleTables(src BindingSource) *RuleTable {
	return &RuleTable{
		src:            src,
		results:        make(map[string]*responsev1.InspectPoliciesResponse_Result),
		constantsCache: make(map[*index.FunctionalCore][]*responsev1.InspectPoliciesResponse_Constant),
		variablesCache: make(map[*index.FunctionalCore][]*responsev1.InspectPoliciesResponse_Variable),
	}
}

// RuleTable is not safe for concurrent use: the internal caches are unsynchronized.
type RuleTable struct {
	src            BindingSource
	results        map[string]*responsev1.InspectPoliciesResponse_Result
	constantsCache map[*index.FunctionalCore][]*responsev1.InspectPoliciesResponse_Constant
	variablesCache map[*index.FunctionalCore][]*responsev1.InspectPoliciesResponse_Variable
}

// Inspect inspects the given rule table and caches the inspection related information internally.
func (rt *RuleTable) Inspect() error {
	if rt.src == nil {
		return fmt.Errorf("binding source is nil")
	}

	rows := rt.src.GetAllRows()

	results := make(map[string]*responsev1.InspectPoliciesResponse_Result)
	actionSets := make(map[string]util.StringSet)
	attrSets := make(map[string]util.StringSet)
	constantSets := make(map[string]util.StringSet)
	derivedRoleSets := make(map[string]util.StringSet)
	variableSets := make(map[string]util.StringSet)
	for _, b := range rows {
		policyKey := namer.PolicyKeyFromFQN(b.OriginFqn)

		result, ok := results[policyKey]
		if !ok {
			result = &responsev1.InspectPoliciesResponse_Result{
				PolicyId: namer.PolicyKeyFromFQN(policyKey),
			}
			results[policyKey] = result
		}

		actionSet := getOrInitStringSet(actionSets, policyKey)
		attrSet := getOrInitStringSet(attrSets, policyKey)
		constantSet := getOrInitStringSet(constantSets, policyKey)
		derivedRoleSet := getOrInitStringSet(derivedRoleSets, policyKey)
		variableSet := getOrInitStringSet(variableSets, policyKey)

		if err := rt.inspectBinding(b, actionSet, attrSet, constantSet, derivedRoleSet, variableSet, result); err != nil {
			return err
		}
	}

	rt.results = results
	return nil
}

func (rt *RuleTable) inspectBinding(
	b *index.Binding,
	actionSet util.StringSet,
	attrSet util.StringSet,
	constantSet util.StringSet,
	derivedRoleSet util.StringSet,
	variableSet util.StringSet,
	result *responsev1.InspectPoliciesResponse_Result,
) error {
	for _, action := range listActions(b) {
		if !actionSet.Contains(action) {
			actionSet[action] = struct{}{}
			result.Actions = append(result.GetActions(), action)
		}
	}

	attrs := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	if err := visitBinding(b, attributeVisitor(attrs)); err != nil {
		return err
	}
	for key, attr := range attrs {
		if !attrSet.Contains(key) {
			attrSet[key] = struct{}{}
			result.Attributes = append(result.GetAttributes(), attr)
		}
	}

	rowConstants, err := rt.listConstants(b)
	if err != nil {
		return err
	}
	for _, constant := range rowConstants {
		if !constantSet.Contains(constant.Name) {
			constantSet[constant.Name] = struct{}{}
			result.Constants = append(result.GetConstants(), constant)
		}
	}

	if derivedRole := getDerivedRole(b); derivedRole != nil {
		if !derivedRoleSet.Contains(derivedRole.Name) {
			derivedRoleSet[derivedRole.Name] = struct{}{}
			result.DerivedRoles = append(result.GetDerivedRoles(), derivedRole)
		}
	}

	for _, variable := range rt.listVariables(b) {
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

func getOrInitStringSet(m map[string]util.StringSet, key string) util.StringSet {
	if s, ok := m[key]; ok {
		return s
	}
	s := make(util.StringSet)
	m[key] = s
	return s
}

func listActions(b *index.Binding) []string {
	n := len(b.AllowActions)
	if b.Action != "" {
		n++
	}

	actions := make([]string, 0, n)
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

// Results are cached per-Core because many bindings share the same Core pointer
// (they differ only in routing dimensions) and structpb conversion is non-trivial.
func (rt *RuleTable) listConstants(b *index.Binding) ([]*responsev1.InspectPoliciesResponse_Constant, error) {
	if cached, ok := rt.constantsCache[b.Core]; ok {
		return cached, nil
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

	rt.constantsCache[b.Core] = constants
	return constants, nil
}

func getDerivedRole(b *index.Binding) *responsev1.InspectPoliciesResponse_DerivedRole {
	if b.OriginDerivedRole == "" {
		return nil
	}

	return &responsev1.InspectPoliciesResponse_DerivedRole{
		Name: b.OriginDerivedRole,
		Kind: responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED,
	}
}

// Results are cached per-Core because many bindings share the same Core pointer
// (they differ only in routing dimensions).
func (rt *RuleTable) listVariables(b *index.Binding) []*responsev1.InspectPoliciesResponse_Variable {
	if cached, ok := rt.variablesCache[b.Core]; ok {
		return cached
	}

	if b.Core.Params == nil {
		rt.variablesCache[b.Core] = nil
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

	rt.variablesCache[b.Core] = variables
	return variables
}
