// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/cel-go/common/ast"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
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
	localVariables := policy.ListVariables(p)
	if _, ok := p.PolicyType.(*policyv1.Policy_ExportVariables); ok {
		sortedLocalVariables := make([]*responsev1.InspectPoliciesResponse_Variable, 0, len(localVariables))
		for _, lv := range localVariables {
			sortedLocalVariables = append(sortedLocalVariables, lv)
		}
		sort.Slice(sortedLocalVariables, func(i, j int) bool {
			return sortedLocalVariables[i].Name < sortedLocalVariables[j].Name
		})

		if len(localVariables) > 0 {
			pol.results[policyID] = &responsev1.InspectPoliciesResponse_Result{
				Variables: sortedLocalVariables,
				PolicyId:  storeIdentifier,
			}
		}

		return nil
	}

	referencedDerivedRoles, referencedVariables, err := pol.inspectDefinitionsAndRules(p)
	if err != nil {
		return fmt.Errorf("failed to inspect definitions and rules of the policy %s: %w", policyID, err)
	}

	var derivedRoles []*responsev1.InspectPoliciesResponse_DerivedRole

	if drp := p.GetDerivedRoles(); drp != nil {
		derivedRoles = policy.ListExportedDerivedRoles(drp)
		if len(derivedRoles) > 0 {
			sort.Slice(derivedRoles, func(i, j int) bool {
				return derivedRoles[i].Name < derivedRoles[j].Name
			})
		}
	} else {
		for referenced := range referencedDerivedRoles {
			if toResolve, exists := pol.derivedRolesToResolve[policyID]; !exists {
				pol.derivedRolesToResolve[policyID] = map[string]bool{referenced: false}
			} else {
				toResolve[referenced] = false
			}
		}
	}

	pol.derivedRolesImports[policyID], pol.variableImports[policyID] = pol.listImports(p)

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
	if len(pol.variablesToResolve[policyID]) > 0 {
		sort.Slice(variables, func(i, j int) bool {
			return variables[i].Name < variables[j].Name
		})
	}

	a := policy.ListActions(p)
	sort.Strings(a)
	pol.results[policyID] = &responsev1.InspectPoliciesResponse_Result{
		Actions:      a,
		DerivedRoles: derivedRoles,
		Variables:    variables,
		PolicyId:     storeIdentifier,
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

		sort.Slice(pol.results[policyID].DerivedRoles, func(x, y int) bool {
			return pol.results[policyID].DerivedRoles[x].Name < pol.results[policyID].DerivedRoles[y].Name
		})
	}

	for policyID, variables := range pol.variablesToResolve {
		importedPolicies, ok := pol.variableImports[policyID]
		var missingPolicies []string
		if ok {
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

		sort.Slice(pol.results[policyID].Variables, func(x, y int) bool {
			return pol.results[policyID].Variables[x].Name < pol.results[policyID].Variables[y].Name
		})
	}

	return pol.results, nil
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

// inspectDefinitionsAndRules inspects the definitions and rules in the given policy to find references to the derived roles and variables.
func (pol *Policy) inspectDefinitionsAndRules(p *policyv1.Policy) (referencedDerivedRoles, referencedVariables map[string]struct{}, err error) {
	referencedDerivedRoles = make(map[string]struct{})
	referencedVariables = make(map[string]struct{})
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition == nil {
				continue
			}

			if err := pol.referencedVariableNamesInCondition(def.Condition, referencedVariables); err != nil {
				return nil, nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if action.Condition == nil {
					continue
				}

				if err := pol.referencedVariableNamesInCondition(action.Condition, referencedVariables); err != nil {
					return nil, nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
				}
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		for _, rule := range pt.ResourcePolicy.Rules {
			pol.referencedDerivedRolesInResourceRule(rule, referencedDerivedRoles)

			if rule.Condition == nil {
				continue
			}

			if err := pol.referencedVariableNamesInCondition(rule.Condition, referencedVariables); err != nil {
				return nil, nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
			}
		}
	}

	return referencedDerivedRoles, referencedVariables, nil
}

func (pol *Policy) referencedDerivedRolesInResourceRule(rule *policyv1.ResourceRule, out map[string]struct{}) {
	for _, derivedRole := range rule.DerivedRoles {
		out[derivedRole] = struct{}{}
	}
}

func (pol *Policy) referencedVariableNamesInCondition(condition *policyv1.Condition, out map[string]struct{}) error {
	c, err := compile.Condition(condition)
	if err != nil {
		return fmt.Errorf("failed to compile condition: %w", err)
	}

	if err := pol.referencedVariableNamesInCompiledCondition(c, out); err != nil {
		return fmt.Errorf("failed to find referenced variable names in compiled condition: %w", err)
	}

	return nil
}

func (pol *Policy) referencedVariableNamesInCompiledCondition(condition *runtimev1.Condition, out map[string]struct{}) error {
	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		for _, condition := range op.All.Expr {
			if err := pol.referencedVariableNamesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced variable names in all condition: %w", err)
			}
		}
	case *runtimev1.Condition_Any:
		for _, condition := range op.Any.Expr {
			if err := pol.referencedVariableNamesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced variable names in any condition: %w", err)
			}
		}
	case *runtimev1.Condition_Expr:
		exprAST, err := ast.ToAST(op.Expr.Checked)
		if err != nil {
			return fmt.Errorf("failed to convert checked expression %s to AST: %w", op.Expr.Checked, err)
		}

		action := func(varName string) {
			out[varName] = struct{}{}
		}
		ast.PreOrderVisit(exprAST.Expr(), compile.VariableVisitor(action))
	case *runtimev1.Condition_None:
		for _, condition := range op.None.Expr {
			if err := pol.referencedVariableNamesInCompiledCondition(condition, out); err != nil {
				return fmt.Errorf("failed to find referenced variable names in none condition: %w", err)
			}
		}
	}

	return nil
}
