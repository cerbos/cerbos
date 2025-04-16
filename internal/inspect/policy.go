// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sort"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

type loadPolicyFn func(ctx context.Context, policyKey ...string) ([]*policy.Wrapper, error)

func Policies() *Policy {
	return &Policy{
		derivedRolesImports:   make(map[string][]string),
		derivedRolesToResolve: make(map[string]map[string]bool),
		constantImports:       make(map[string][]string),
		constantsToResolve:    make(map[string]map[string]bool),
		variableImports:       make(map[string][]string),
		variablesToResolve:    make(map[string]map[string]bool),
		results:               make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}
}

type Policy struct {
	derivedRolesImports   map[string][]string
	derivedRolesToResolve map[string]map[string]bool
	constantImports       map[string][]string
	constantsToResolve    map[string]map[string]bool
	variableImports       map[string][]string
	variablesToResolve    map[string]map[string]bool
	results               map[string]*responsev1.InspectPoliciesResponse_Result
}

// Inspect inspects the given policy and caches the inspection related information internally.
func (pol *Policy) Inspect(p *policyv1.Policy) error {
	if p == nil {
		return fmt.Errorf("policy is nil")
	}

	storeIdentifier := ""
	if p.Metadata != nil {
		storeIdentifier = p.Metadata.StoreIdentifier
	}

	policyID := namer.PolicyKey(p)
	pol.derivedRolesImports[policyID], pol.constantImports[policyID], pol.variableImports[policyID] = pol.listImports(p)

	attributes, err := pol.listReferencedAttributes(p)
	if err != nil {
		return fmt.Errorf("failed to list referenced attributes in the policy %s: %w", policyID, err)
	}

	var derivedRoles []*responsev1.InspectPoliciesResponse_DerivedRole
	//nolint:nestif
	if drp := p.GetDerivedRoles(); drp != nil {
		derivedRoles = policy.ListExportedDerivedRoles(drp)
		if len(derivedRoles) > 0 {
			slices.SortFunc(derivedRoles, func(a, b *responsev1.InspectPoliciesResponse_DerivedRole) int {
				return cmp.Compare(a.GetName(), b.GetName())
			})
		}
	} else if rp := p.GetResourcePolicy(); rp != nil {
		referencedDerivedRoles := pol.listReferencedDerivedRoles(rp)
		for referenced := range referencedDerivedRoles {
			if toResolve, exists := pol.derivedRolesToResolve[policyID]; !exists {
				pol.derivedRolesToResolve[policyID] = map[string]bool{referenced: false}
			} else {
				toResolve[referenced] = false
			}
		}
	}

	referencedConstants, err := pol.listReferencedConstants(p)
	if err != nil {
		return fmt.Errorf("failed to list referenced constants in the policy %s: %w", policyID, err)
	}

	localConstants := policy.ListConstants(p)
	for referenced := range referencedConstants {
		if v, ok := localConstants[referenced]; ok {
			v.Used = true
		} else {
			if toResolve, exists := pol.constantsToResolve[policyID]; !exists {
				pol.constantsToResolve[policyID] = map[string]bool{referenced: false}
			} else {
				toResolve[referenced] = false
			}
		}
	}

	constants := make([]*responsev1.InspectPoliciesResponse_Constant, 0, len(localConstants))
	for _, lc := range localConstants {
		constants = append(constants, lc)
	}

	// sort constants if there is nothing to resolve since we are not going to modify constants in the future.
	if len(pol.constantsToResolve[policyID]) == 0 {
		slices.SortFunc(constants, func(a, b *responsev1.InspectPoliciesResponse_Constant) int {
			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	referencedVariables, err := pol.listReferencedVariables(p)
	if err != nil {
		return fmt.Errorf("failed to list referenced variables in the policy %s: %w", policyID, err)
	}

	localVariables := policy.ListVariables(p)
	for referenced := range referencedVariables {
		if v, ok := localVariables[referenced]; ok {
			v.Used = true
		} else {
			if toResolve, exists := pol.variablesToResolve[policyID]; !exists {
				pol.variablesToResolve[policyID] = map[string]bool{referenced: false}
			} else {
				toResolve[referenced] = false
			}
		}
	}

	variables := make([]*responsev1.InspectPoliciesResponse_Variable, 0, len(localVariables))
	for _, lv := range localVariables {
		variables = append(variables, lv)
	}

	// sort variables if there is nothing to resolve since we are not going to modify variables in the future.
	if len(pol.variablesToResolve[policyID]) == 0 {
		slices.SortFunc(variables, func(a, b *responsev1.InspectPoliciesResponse_Variable) int {
			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	actions := policy.ListActions(p)
	sort.Strings(actions)
	pol.results[policyID] = &responsev1.InspectPoliciesResponse_Result{
		Actions:      actions,
		Attributes:   attributes,
		Constants:    constants,
		DerivedRoles: derivedRoles,
		PolicyId:     storeIdentifier,
		Variables:    variables,
	}

	return nil
}

// Results returns the final inspection results.
func (pol *Policy) Results(ctx context.Context, loadPolicy loadPolicyFn) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	pol.resolveDerivedRoles(ctx, loadPolicy)
	pol.resolveConstants(ctx, loadPolicy)
	if err := pol.resolveVariables(ctx, loadPolicy); err != nil {
		return nil, fmt.Errorf("failed to resolve variables: %w", err)
	}

	return pol.results, nil
}

func (pol *Policy) resolveDerivedRoles(ctx context.Context, loadPolicy loadPolicyFn) {
	for policyID, derivedRoles := range pol.derivedRolesToResolve {
		importedPolicies, ok := pol.derivedRolesImports[policyID]
		var missingPolicies []string
		if ok {
			for _, importedPolicyID := range importedPolicies {
				if importedResult, ok := pol.results[importedPolicyID]; ok {
					for _, importedDerivedRole := range importedResult.DerivedRoles {
						if _, ok := derivedRoles[importedDerivedRole.Name]; ok {
							pol.results[policyID].DerivedRoles = append(pol.results[policyID].DerivedRoles, &responsev1.InspectPoliciesResponse_DerivedRole{
								Name:   importedDerivedRole.Name,
								Kind:   responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED,
								Source: importedPolicyID,
							})
							derivedRoles[importedDerivedRole.Name] = true
						}
					}
				} else {
					missingPolicies = append(missingPolicies, importedPolicyID)
				}
			}
		}

		if loadPolicy != nil {
			if err := storage.BatchLoadPolicy(ctx, storage.MaxPoliciesInBatch, loadPolicy, func(wrapper *policy.Wrapper) error {
				importedDerivedRoles := policy.ListExportedDerivedRoles(wrapper.GetDerivedRoles())
				for _, importedDerivedRole := range importedDerivedRoles {
					if _, ok := derivedRoles[importedDerivedRole.Name]; ok {
						pol.results[policyID].DerivedRoles = append(pol.results[policyID].DerivedRoles, &responsev1.InspectPoliciesResponse_DerivedRole{
							Name:   importedDerivedRole.Name,
							Kind:   responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED,
							Source: namer.PolicyKeyFromFQN(wrapper.FQN),
						})

						derivedRoles[importedDerivedRole.Name] = true
					}
				}

				return nil
			}, missingPolicies...); err != nil {
				continue
			}
		}

		for name, found := range derivedRoles {
			if !found {
				pol.results[policyID].DerivedRoles = append(pol.results[policyID].DerivedRoles, &responsev1.InspectPoliciesResponse_DerivedRole{
					Name:   name,
					Kind:   responsev1.InspectPoliciesResponse_DerivedRole_KIND_UNDEFINED,
					Source: "",
				})
			}
		}

		slices.SortFunc(pol.results[policyID].DerivedRoles, func(a, b *responsev1.InspectPoliciesResponse_DerivedRole) int {
			return cmp.Compare(a.GetName(), b.GetName())
		})
	}
}

func (pol *Policy) resolveConstants(ctx context.Context, loadPolicy loadPolicyFn) {
	for policyID, constants := range pol.constantsToResolve {
		attrs := make(util.StringSet)
		for _, attr := range pol.results[policyID].Attributes {
			attrs[attr.Name] = struct{}{}
		}

		var missingPolicies []string
		if importedPolicies, ok := pol.constantImports[policyID]; ok { //nolint:nestif
			for _, importedPolicyID := range importedPolicies {
				if importedResult, ok := pol.results[importedPolicyID]; ok {
					for _, importedConstant := range importedResult.Constants {
						if _, ok := constants[importedConstant.Name]; ok {
							pol.results[policyID].Constants = append(pol.results[policyID].Constants, &responsev1.InspectPoliciesResponse_Constant{
								Name:   importedConstant.Name,
								Value:  importedConstant.Value,
								Kind:   responsev1.InspectPoliciesResponse_Constant_KIND_IMPORTED,
								Source: importedPolicyID,
								Used:   true,
							})
							constants[importedConstant.Name] = true
						}
					}
				} else {
					missingPolicies = append(missingPolicies, importedPolicyID)
				}
			}
		}

		if loadPolicy != nil {
			if err := storage.BatchLoadPolicy(ctx, storage.MaxPoliciesInBatch, loadPolicy, func(wrapper *policy.Wrapper) error {
				importedConstants := policy.ListConstants(wrapper.Policy)
				for importedConstName, importedConstant := range importedConstants {
					if _, ok := constants[importedConstName]; ok {
						pol.results[policyID].Constants = append(pol.results[policyID].Constants, &responsev1.InspectPoliciesResponse_Constant{
							Name:   importedConstName,
							Value:  importedConstant.Value,
							Kind:   responsev1.InspectPoliciesResponse_Constant_KIND_IMPORTED,
							Source: namer.PolicyKeyFromFQN(wrapper.FQN),
							Used:   true,
						})
						constants[importedConstName] = true
					}
				}

				return nil
			}, missingPolicies...); err != nil {
				continue
			}
		}

		for name, found := range constants {
			if !found {
				pol.results[policyID].Constants = append(pol.results[policyID].Constants, &responsev1.InspectPoliciesResponse_Constant{
					Name: name,
					Kind: responsev1.InspectPoliciesResponse_Constant_KIND_UNDEFINED,
					Used: true,
				})
			}
		}

		slices.SortFunc(pol.results[policyID].Constants, func(a, b *responsev1.InspectPoliciesResponse_Constant) int {
			return cmp.Compare(a.GetName(), b.GetName())
		})
	}
}

func (pol *Policy) resolveVariables(ctx context.Context, loadPolicy loadPolicyFn) error {
	for policyID, variables := range pol.variablesToResolve {
		attrs := make(util.StringSet)
		for _, attr := range pol.results[policyID].Attributes {
			attrs[attr.Name] = struct{}{}
		}

		var missingPolicies []string
		if importedPolicies, ok := pol.variableImports[policyID]; ok { //nolint:nestif
			for _, importedPolicyID := range importedPolicies {
				if importedResult, ok := pol.results[importedPolicyID]; ok {
					for _, importedVariable := range importedResult.Variables {
						if _, ok := variables[importedVariable.Name]; ok {
							pol.results[policyID].Variables = append(pol.results[policyID].Variables, &responsev1.InspectPoliciesResponse_Variable{
								Name:   importedVariable.Name,
								Value:  importedVariable.Value,
								Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED,
								Source: importedPolicyID,
								Used:   true,
							})
							variables[importedVariable.Name] = true

							referencedAttributes := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
							if err := visitExpr(importedVariable.Value, attributeVisitor(referencedAttributes)); err != nil {
								return fmt.Errorf("failed to find referenced attributes in imported variable: %w", err)
							}

							if len(referencedAttributes) > 0 {
								for _, attr := range referencedAttributes {
									if !attrs.Contains(attr.Name) {
										pol.results[policyID].Attributes = append(pol.results[policyID].Attributes, attr)
										attrs[attr.Name] = struct{}{}
									}
								}
							}
						}
					}
				} else {
					missingPolicies = append(missingPolicies, importedPolicyID)
				}
			}
		}

		if loadPolicy != nil {
			if err := storage.BatchLoadPolicy(ctx, storage.MaxPoliciesInBatch, loadPolicy, func(wrapper *policy.Wrapper) error {
				importedVariables := policy.ListVariables(wrapper.Policy)
				for importedVarName, importedVariable := range importedVariables {
					if _, ok := variables[importedVarName]; ok {
						pol.results[policyID].Variables = append(pol.results[policyID].Variables, &responsev1.InspectPoliciesResponse_Variable{
							Name:   importedVarName,
							Value:  importedVariable.Value,
							Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED,
							Source: namer.PolicyKeyFromFQN(wrapper.FQN),
							Used:   true,
						})
						variables[importedVarName] = true

						referencedAttributes := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
						if err := visitExpr(importedVariable.Value, attributeVisitor(referencedAttributes)); err != nil {
							return fmt.Errorf("failed to find referenced attributes in imported variable: %w", err)
						}

						if len(referencedAttributes) > 0 {
							for _, attr := range referencedAttributes {
								if !attrs.Contains(attr.Name) {
									pol.results[policyID].Attributes = append(pol.results[policyID].Attributes, attr)
									attrs[attr.Name] = struct{}{}
								}
							}
						}
					}
				}

				return nil
			}, missingPolicies...); err != nil {
				continue
			}
		}

		for name, found := range variables {
			if !found {
				pol.results[policyID].Variables = append(pol.results[policyID].Variables, &responsev1.InspectPoliciesResponse_Variable{
					Name:   name,
					Value:  "null",
					Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_UNDEFINED,
					Source: "",
					Used:   true,
				})
			}
		}

		slices.SortFunc(pol.results[policyID].Attributes, func(a, b *responsev1.InspectPoliciesResponse_Attribute) int {
			return cmp.Compare(a.GetName(), b.GetName())
		})

		slices.SortFunc(pol.results[policyID].Variables, func(a, b *responsev1.InspectPoliciesResponse_Variable) int {
			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return nil
}

// listReferencedAttributes lists the attributes referenced from the conditions and variables in the given policy.
func (pol *Policy) listReferencedAttributes(p *policyv1.Policy) ([]*responsev1.InspectPoliciesResponse_Attribute, error) {
	if p == nil {
		return nil, nil
	}

	attrs := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	if err := visitPolicy(p, attributeVisitor(attrs)); err != nil {
		return nil, err
	}
	return attributeList(attrs), nil
}

// listReferencedDerivedRoles lists the referenced derived roles in the given resource policy.
func (pol *Policy) listReferencedDerivedRoles(rp *policyv1.ResourcePolicy) map[string]struct{} {
	if rp == nil {
		return nil
	}

	derivedRoles := make(map[string]struct{})
	for _, rule := range rp.Rules {
		for _, derivedRole := range rule.DerivedRoles {
			derivedRoles[derivedRole] = struct{}{}
		}
	}

	return derivedRoles
}

// listReferencedConstants lists the constants referenced from the conditions in the given policy.
func (pol *Policy) listReferencedConstants(p *policyv1.Policy) (map[string]*responsev1.InspectPoliciesResponse_Constant, error) {
	if p == nil {
		return nil, nil
	}

	consts := make(map[string]*responsev1.InspectPoliciesResponse_Constant)
	return consts, visitPolicy(p, constantVisitor(consts))
}

// listReferencedVariables lists the variables referenced from the conditions in the given policy.
func (pol *Policy) listReferencedVariables(p *policyv1.Policy) (map[string]*responsev1.InspectPoliciesResponse_Variable, error) {
	if p == nil {
		return nil, nil
	}

	vars := make(map[string]*responsev1.InspectPoliciesResponse_Variable)
	return vars, visitPolicy(p, variableVisitor(vars))
}

// listImports lists the derived roles and export constants/variables imported by the given policy.
func (pol *Policy) listImports(p *policyv1.Policy) (derivedRoleImports, constantImports, variableImports []string) {
	type constantsAndVariables interface {
		GetConstants() *policyv1.Constants
		GetVariables() *policyv1.Variables
	}

	setConstantAndVariableImports := func(source constantsAndVariables) {
		constantImports = policyKeys(source.GetConstants().GetImport(), namer.ExportConstantsFQN)
		variableImports = policyKeys(source.GetVariables().GetImport(), namer.ExportVariablesFQN)
	}

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		setConstantAndVariableImports(pt.DerivedRoles)
	case *policyv1.Policy_PrincipalPolicy:
		setConstantAndVariableImports(pt.PrincipalPolicy)
	case *policyv1.Policy_ResourcePolicy:
		setConstantAndVariableImports(pt.ResourcePolicy)
		derivedRoleImports = policyKeys(pt.ResourcePolicy.ImportDerivedRoles, namer.DerivedRolesFQN)
	}

	return derivedRoleImports, constantImports, variableImports
}

func policyKeys(names []string, fqn func(string) string) []string {
	if len(names) == 0 {
		return nil
	}

	keys := make([]string, len(names))
	for i, name := range names {
		keys[i] = namer.PolicyKeyFromFQN(fqn(name))
	}
	return keys
}
