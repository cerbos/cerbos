// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

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

func New() *Inspect {
	return &Inspect{
		toResolve: make(map[string]map[string]struct{}),
		imports:   make(map[string][]string),
		results:   make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}
}

type Inspect struct {
	toResolve map[string]map[string]struct{}
	imports   map[string][]string
	results   map[string]*responsev1.InspectPoliciesResponse_Result
}

func (i *Inspect) Inspect(p *policyv1.Policy) error {
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
			i.results[policyID] = &responsev1.InspectPoliciesResponse_Result{
				Variables: variables,
			}
		}

		return nil
	}

	referencedVariables, err := i.inspectConditions(p)
	if err != nil {
		return fmt.Errorf("failed to inspect conditions of the policy %s: %w", policyID, err)
	}
	i.imports[policyID] = i.inspectImports(p)

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
			if i.toResolve[policyID] == nil {
				i.toResolve[policyID] = make(map[string]struct{})
			}

			toResolve = true
			i.toResolve[policyID][name] = struct{}{}
		}
	}

	if !toResolve {
		sort.Slice(variables, func(i, j int) bool {
			return variables[i].Name < variables[j].Name
		})
	}

	a := policy.ListActions(p)
	sort.Strings(a)
	if len(a) > 0 || len(variables) > 0 {
		i.results[policyID] = &responsev1.InspectPoliciesResponse_Result{
			Actions:   a,
			Variables: variables,
		}
	}

	return nil
}

func (i *Inspect) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	for policyID, variables := range i.toResolve {
		importedPolicies, ok := i.imports[policyID]
		if !ok {
			for name := range variables {
				i.results[policyID].Variables = append(i.results[policyID].Variables, &responsev1.InspectPoliciesResponse_Variable{
					Name:   name,
					Value:  "null",
					Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_UNDEFINED,
					Source: "",
					Used:   true,
				})
			}
			sort.Slice(i.results[policyID].Variables, func(x, y int) bool {
				return i.results[policyID].Variables[x].Name < i.results[policyID].Variables[y].Name
			})

			continue
		}

		for _, importedPolicyID := range importedPolicies {
			importedResult, ok := i.results[importedPolicyID]
			if !ok {
				return nil, fmt.Errorf("failed to find imported policy %s in the inspected policies", importedPolicyID)
			}

			for _, importedVariable := range importedResult.Variables {
				if _, ok := variables[importedVariable.Name]; ok {
					i.results[policyID].Variables = append(i.results[policyID].Variables, &responsev1.InspectPoliciesResponse_Variable{
						Name:   importedVariable.Name,
						Value:  importedVariable.Value,
						Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED,
						Source: importedPolicyID,
						Used:   true,
					})
				}
			}

			sort.Slice(i.results[policyID].Variables, func(x, y int) bool {
				return i.results[policyID].Variables[x].Name < i.results[policyID].Variables[y].Name
			})
		}
	}

	return i.results, nil
}

// inspectImports inspects the export variables imports of the policy.
func (i *Inspect) inspectImports(p *policyv1.Policy) []string {
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
func (i *Inspect) inspectConditions(p *policyv1.Policy) (map[string]struct{}, error) {
	referencedVariables := make(map[string]struct{})
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition == nil {
				continue
			}

			referencedVariableNames, err := i.referencedVariableNamesInCondition(def.Condition)
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

				referencedVariableNames, err := i.referencedVariableNamesInCondition(action.Condition)
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

			referencedVariableNames, err := i.referencedVariableNamesInCondition(rule.Condition)
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

func (i *Inspect) referencedVariableNamesInCondition(condition *policyv1.Condition) (map[string]struct{}, error) {
	c, err := compile.Condition(condition)
	if err != nil {
		return nil, fmt.Errorf("failed to compile condition: %w", err)
	}

	referencedVariableNames, err := i.referencedVariableNamesInCompiledCondition(c)
	if err != nil {
		return nil, fmt.Errorf("failed to find referenced variable names in compiled condition: %w", err)
	}

	return referencedVariableNames, nil
}

func (i *Inspect) referencedVariableNamesInCompiledCondition(condition *runtimev1.Condition) (map[string]struct{}, error) {
	referencedVariableNames := make(map[string]struct{})
	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		for _, condition := range op.All.Expr {
			referenced, err := i.referencedVariableNamesInCompiledCondition(condition)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in all condition: %w", err)
			}

			for varName := range referenced {
				referencedVariableNames[varName] = struct{}{}
			}
		}
	case *runtimev1.Condition_Any:
		for _, condition := range op.Any.Expr {
			referenced, err := i.referencedVariableNamesInCompiledCondition(condition)
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
			referenced, err := i.referencedVariableNamesInCompiledCondition(condition)
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
