// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/google/cel-go/common/ast"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

func Policies() *Policy {
	return &Policy{
		derivedRolesImports:   make(map[string][]string),
		derivedRolesToResolve: make(map[string]map[string]bool),
		variableImports:       make(map[string][]string),
		variablesToResolve:    make(map[string]map[string]bool),
		results:               make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}
}

type Policy struct {
	derivedRolesImports   map[string][]string
	derivedRolesToResolve map[string]map[string]bool
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
	pol.derivedRolesImports[policyID], pol.variableImports[policyID] = pol.listImports(p)

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
		DerivedRoles: derivedRoles,
		PolicyId:     storeIdentifier,
		Variables:    variables,
	}

	return nil
}

type loadPolicyFn func(ctx context.Context, policyKey ...string) ([]*policy.Wrapper, error)

// Results returns the final inspection results.
func (pol *Policy) Results(ctx context.Context, loadPolicy loadPolicyFn) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
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
				importedDerivedRoles := policy.ListExportedDerivedRoles(wrapper.Policy.GetDerivedRoles())
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

	for policyID, variables := range pol.variablesToResolve {
		importedPolicies, ok := pol.variableImports[policyID]
		var missingPolicies []string
		if ok { //nolint:nestif
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
							if err := pol.referencedAttributesInExpr(importedVariable.Value, referencedAttributes); err != nil {
								return nil, fmt.Errorf("failed to find referenced attributes in imported variable: %w", err)
							}

							if len(referencedAttributes) > 0 {
								ss := make(util.StringSet)
								for _, attr := range pol.results[policyID].Attributes {
									ss[attr.Name] = struct{}{}
								}

								for _, attr := range referencedAttributes {
									if !ss.Contains(attr.Name) {
										pol.results[policyID].Attributes = append(pol.results[policyID].Attributes, attr)
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
						if err := pol.referencedAttributesInExpr(importedVariable.Value, referencedAttributes); err != nil {
							return fmt.Errorf("failed to find referenced attributes in imported variable: %w", err)
						}

						if len(referencedAttributes) > 0 {
							ss := make(util.StringSet)
							for _, attr := range pol.results[policyID].Attributes {
								ss[attr.Name] = struct{}{}
							}

							for _, attr := range referencedAttributes {
								if !ss.Contains(attr.Name) {
									pol.results[policyID].Attributes = append(pol.results[policyID].Attributes, attr)
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

	return pol.results, nil
}

// listReferencedAttributes lists the attributes referenced from the conditions and variables in the given policy.
func (pol *Policy) listReferencedAttributes(p *policyv1.Policy) ([]*responsev1.InspectPoliciesResponse_Attribute, error) {
	if p == nil {
		return nil, nil
	}

	referencedAttributes := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition == nil {
				continue
			}

			if err := pol.referencedAttributesInCondition(def.Condition, referencedAttributes); err != nil {
				return nil, fmt.Errorf("failed to find referenced attributes in the derived role definition: %w", err)
			}
		}

		if pt.DerivedRoles.Variables != nil {
			for _, expr := range pt.DerivedRoles.Variables.Local {
				if err := pol.referencedAttributesInExpr(expr, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the derived roles local variable: %w", err)
				}
			}
		}
	case *policyv1.Policy_ExportVariables:
		for _, expr := range pt.ExportVariables.Definitions {
			if err := pol.referencedAttributesInExpr(expr, referencedAttributes); err != nil {
				return nil, fmt.Errorf("failed to find referenced attributes in exported variable definition: %w", err)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if action.Condition == nil {
					continue
				}

				if err := pol.referencedAttributesInCondition(action.Condition, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the principal policy rule: %w", err)
				}
			}
		}

		if pt.PrincipalPolicy.Variables != nil {
			for _, expr := range pt.PrincipalPolicy.Variables.Local {
				if err := pol.referencedAttributesInExpr(expr, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the principal policy local variable: %w", err)
				}
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		for _, rule := range pt.ResourcePolicy.Rules {
			if rule.Condition == nil {
				continue
			}

			if err := pol.referencedAttributesInCondition(rule.Condition, referencedAttributes); err != nil {
				return nil, fmt.Errorf("failed to find referenced attributes in the resource policy rule: %w", err)
			}
		}

		if pt.ResourcePolicy.Variables != nil {
			for _, expr := range pt.ResourcePolicy.Variables.Local {
				if err := pol.referencedAttributesInExpr(expr, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the resource policy local variable: %w", err)
				}
			}
		}
	}

	attributes := make([]*responsev1.InspectPoliciesResponse_Attribute, 0, len(referencedAttributes))
	for _, attr := range referencedAttributes {
		attributes = append(attributes, &responsev1.InspectPoliciesResponse_Attribute{
			Name: attr.Name,
			Kind: attr.Kind,
		})
	}

	if len(attributes) > 0 {
		slices.SortFunc(attributes, func(a, b *responsev1.InspectPoliciesResponse_Attribute) int {
			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return attributes, nil
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

// listReferencedVariables lists the variables referenced from the conditions in the given policy.
func (pol *Policy) listReferencedVariables(p *policyv1.Policy) (map[string]*responsev1.InspectPoliciesResponse_Variable, error) {
	if p == nil {
		return nil, nil
	}

	referencedVariables := make(map[string]*responsev1.InspectPoliciesResponse_Variable)
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition == nil {
				continue
			}

			if err := pol.referencedVariablesInCondition(def.Condition, referencedVariables); err != nil {
				return nil, fmt.Errorf("failed to find referenced variables in the derived role definition: %w", err)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if action.Condition == nil {
					continue
				}

				if err := pol.referencedVariablesInCondition(action.Condition, referencedVariables); err != nil {
					return nil, fmt.Errorf("failed to find referenced variables in the principal policy rule: %w", err)
				}
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		for _, rule := range pt.ResourcePolicy.Rules {
			if rule.Condition == nil {
				continue
			}

			if err := pol.referencedVariablesInCondition(rule.Condition, referencedVariables); err != nil {
				return nil, fmt.Errorf("failed to find referenced variables in the resource policy rule: %w", err)
			}
		}
	}

	return referencedVariables, nil
}

// listImports lists the derived roles and export variables imported by the given policy.
func (pol *Policy) listImports(p *policyv1.Policy) (derivedRoleImports, variableImports []string) {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		if pt.DerivedRoles.Variables != nil {
			for _, variablesName := range pt.DerivedRoles.Variables.Import {
				policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
				variableImports = append(variableImports, policyID)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		if pt.PrincipalPolicy.Variables != nil {
			for _, variablesName := range pt.PrincipalPolicy.Variables.Import {
				policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
				variableImports = append(variableImports, policyID)
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		if pt.ResourcePolicy.ImportDerivedRoles != nil {
			for _, roleSetName := range pt.ResourcePolicy.ImportDerivedRoles {
				policyID := namer.PolicyKeyFromFQN(namer.DerivedRolesFQN(roleSetName))
				derivedRoleImports = append(derivedRoleImports, policyID)
			}
		}

		if pt.ResourcePolicy.Variables != nil {
			for _, variablesName := range pt.ResourcePolicy.Variables.Import {
				policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
				variableImports = append(variableImports, policyID)
			}
		}
	}

	return derivedRoleImports, variableImports
}

func (pol *Policy) referencedAttributesInExpr(expr string, referencedAttributes map[string]*responsev1.InspectPoliciesResponse_Attribute) error {
	c := &policyv1.Condition{
		Condition: &policyv1.Condition_Match{
			Match: &policyv1.Match{
				Op: &policyv1.Match_Expr{
					Expr: expr,
				},
			},
		},
	}

	if err := pol.referencedAttributesInCondition(c, referencedAttributes); err != nil {
		return fmt.Errorf("failed to find referenced attributes in the expression: %w", err)
	}

	return nil
}

func (pol *Policy) referencedAttributesInCondition(condition *policyv1.Condition, referencedAttributes map[string]*responsev1.InspectPoliciesResponse_Attribute) error {
	c, err := compile.Condition(condition)
	if err != nil {
		return fmt.Errorf("failed to compile the condition: %w", err)
	}

	if err := referencedAttributesInCompiledCondition(c, referencedAttributes); err != nil {
		return fmt.Errorf("failed to find referenced attributes in the compiled condition: %w", err)
	}

	return nil
}

func (pol *Policy) referencedVariablesInCondition(condition *policyv1.Condition, referencedVariables map[string]*responsev1.InspectPoliciesResponse_Variable) error {
	c, err := compile.Condition(condition)
	if err != nil {
		return fmt.Errorf("failed to compile the condition: %w", err)
	}

	if err := pol.referencedVariablesInCompiledCondition(c, referencedVariables); err != nil {
		return fmt.Errorf("failed to find referenced variables in the compiled condition: %w", err)
	}

	return nil
}

func (pol *Policy) referencedVariablesInCompiledCondition(condition *runtimev1.Condition, out map[string]*responsev1.InspectPoliciesResponse_Variable) error {
	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		for _, condition := range op.All.Expr {
			if err := pol.referencedVariablesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced variables in the 'all' expression: %w", err)
			}
		}
	case *runtimev1.Condition_Any:
		for _, condition := range op.Any.Expr {
			if err := pol.referencedVariablesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced variables in the 'any' expression: %w", err)
			}
		}
	case *runtimev1.Condition_Expr:
		exprAST, err := ast.ToAST(op.Expr.Checked)
		if err != nil {
			return fmt.Errorf("failed to convert checked expression %s to AST: %w", op.Expr.Checked, err)
		}

		ast.PreOrderVisit(
			exprAST.Expr(),
			variableVisitor(
				func(name, value string) {
					out[name] = &responsev1.InspectPoliciesResponse_Variable{
						Name:  name,
						Value: value,
						Kind:  responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN,
						Used:  true,
					}
				},
			),
		)
	case *runtimev1.Condition_None:
		for _, condition := range op.None.Expr {
			if err := pol.referencedVariablesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced variables in the 'none' expression: %w", err)
			}
		}
	}

	return nil
}
