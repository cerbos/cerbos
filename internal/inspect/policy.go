// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"
	"sort"

	"github.com/google/cel-go/common/ast"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func Policies() *Policy {
	return &Policy{
		toResolve: make(map[string]map[string]bool),
		imports:   make(map[string][]string),
		results:   make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}
}

type Policy struct {
	toResolve map[string]map[string]bool
	imports   map[string][]string
	results   map[string]*responsev1.InspectPoliciesResponse_Result
}

// Inspect inspects the given policy and caches the inspection related information internally.
func (pol *Policy) Inspect(p *policyv1.Policy) error {
	if p == nil {
		return fmt.Errorf("policy is nil")
	}

	policyID := namer.PolicyKey(p)
	variables := policy.ListVariables(p)
	if _, ok := p.PolicyType.(*policyv1.Policy_ExportVariables); ok {
		sort.Slice(variables, func(i, j int) bool {
			return variables[i].Name < variables[j].Name
		})

		if len(variables) > 0 {
			pol.results[policyID] = &responsev1.InspectPoliciesResponse_Result{
				Variables: variables,
			}
		}

		return nil
	}

	referencedVariables, err := pol.inspectConditions(p)
	if err != nil {
		return fmt.Errorf("failed to inspect conditions of the policy %s: %w", policyID, err)
	}
	pol.imports[policyID] = pol.inspectImports(p)

	localVariables := make(map[string]struct{})
	for _, variable := range variables {
		localVariables[variable.Name] = struct{}{}
		if _, ok := referencedVariables[variable.Name]; ok {
			variable.Used = true
		}
	}

	toResolve := false
	for name := range referencedVariables {
		if _, ok := localVariables[name]; !ok {
			if pol.toResolve[policyID] == nil {
				pol.toResolve[policyID] = make(map[string]bool)
			}

			toResolve = true
			pol.toResolve[policyID][name] = false
		}
	}

	// sort variables if there is nothing to resolve since we are not going to modify variables in the future.
	if !toResolve {
		sort.Slice(variables, func(i, j int) bool {
			return variables[i].Name < variables[j].Name
		})
	}

	a := policy.ListActions(p)
	sort.Strings(a)
	if len(a) > 0 || len(variables) > 0 {
		pol.results[policyID] = &responsev1.InspectPoliciesResponse_Result{
			Actions:   a,
			Variables: variables,
		}
	}

	return nil
}

// Results returns the final inspection results.
func (pol *Policy) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	for policyID, variables := range pol.toResolve {
		importedPolicies, ok := pol.imports[policyID]
		if ok {
			for _, importedPolicyID := range importedPolicies {
				importedResult, ok := pol.results[importedPolicyID]
				if !ok {
					return nil, fmt.Errorf("failed to find imported policy %s in the inspected policies", importedPolicyID)
				}

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

// MissingImports returns the list of exportVariables not present in the inspected policy list.
func (pol *Policy) MissingImports() []string {
	m := make(map[string]struct{})
	for _, imports := range pol.imports {
		for _, importedPolicyID := range imports {
			if _, ok := pol.results[importedPolicyID]; !ok {
				m[importedPolicyID] = struct{}{}
			}
		}
	}

	missingImports := make([]string, 0, len(m))
	for policyID := range m {
		missingImports = append(missingImports, policyID)
	}

	return missingImports
}

// inspectImports inspects the export variables imports of the policy.
func (pol *Policy) inspectImports(p *policyv1.Policy) []string {
	var imports []string
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		if pt.DerivedRoles.Variables != nil {
			for _, variablesName := range pt.DerivedRoles.Variables.Import {
				policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
				imports = append(imports, policyID)
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		if pt.PrincipalPolicy.Variables != nil {
			for _, variablesName := range pt.PrincipalPolicy.Variables.Import {
				policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
				imports = append(imports, policyID)
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		if pt.ResourcePolicy.Variables != nil {
			for _, variablesName := range pt.ResourcePolicy.Variables.Import {
				policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
				imports = append(imports, policyID)
			}
		}
	}

	return imports
}

// inspectConditions inspects the conditions in the given policy to find references to the variables.
func (pol *Policy) inspectConditions(p *policyv1.Policy) (map[string]struct{}, error) {
	referencedVariables := make(map[string]struct{})
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition == nil {
				continue
			}

			referencedVariableNames, err := pol.referencedVariableNamesInCondition(def.Condition)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
			}

			for name := range referencedVariableNames {
				referencedVariables[name] = struct{}{}
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if action.Condition == nil {
					continue
				}

				referencedVariableNames, err := pol.referencedVariableNamesInCondition(action.Condition)
				if err != nil {
					return nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
				}

				for name := range referencedVariableNames {
					referencedVariables[name] = struct{}{}
				}
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		for _, rule := range pt.ResourcePolicy.Rules {
			if rule.Condition == nil {
				continue
			}

			referencedVariableNames, err := pol.referencedVariableNamesInCondition(rule.Condition)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
			}

			for name := range referencedVariableNames {
				referencedVariables[name] = struct{}{}
			}
		}
	}

	return referencedVariables, nil
}

func (pol *Policy) referencedVariableNamesInCondition(condition *policyv1.Condition) (map[string]struct{}, error) {
	c, err := compile.Condition(condition)
	if err != nil {
		return nil, fmt.Errorf("failed to compile condition: %w", err)
	}

	referencedVariableNames, err := pol.referencedVariableNamesInCompiledCondition(c)
	if err != nil {
		return nil, fmt.Errorf("failed to find referenced variable names in compiled condition: %w", err)
	}

	return referencedVariableNames, nil
}

func (pol *Policy) referencedVariableNamesInCompiledCondition(condition *runtimev1.Condition) (map[string]struct{}, error) {
	referencedVariableNames := make(map[string]struct{})
	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		for _, condition := range op.All.Expr {
			referenced, err := pol.referencedVariableNamesInCompiledCondition(condition)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in all condition: %w", err)
			}

			for varName := range referenced {
				referencedVariableNames[varName] = struct{}{}
			}
		}
	case *runtimev1.Condition_Any:
		for _, condition := range op.Any.Expr {
			referenced, err := pol.referencedVariableNamesInCompiledCondition(condition)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in any condition: %w", err)
			}

			for varName := range referenced {
				referencedVariableNames[varName] = struct{}{}
			}
		}
	case *runtimev1.Condition_Expr:
		exprAST, err := ast.ToAST(op.Expr.Checked)
		if err != nil {
			return nil, fmt.Errorf("failed to convert checked expression %s to AST: %w", op.Expr.Checked, err)
		}

		action := func(varName string) {
			referencedVariableNames[varName] = struct{}{}
		}
		ast.PreOrderVisit(exprAST.Expr(), compile.VariableVisitor(action))
	case *runtimev1.Condition_None:
		for _, condition := range op.None.Expr {
			referenced, err := pol.referencedVariableNamesInCompiledCondition(condition)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in none condition: %w", err)
			}

			for varName := range referenced {
				referencedVariableNames[varName] = struct{}{}
			}
		}
	}

	return referencedVariableNames, nil
}
