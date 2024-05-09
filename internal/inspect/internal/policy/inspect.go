// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/cel-go/common/ast"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/inspect/internal"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func New() *Inspect {
	return &Inspect{
		inspections: make(map[string]*internal.Inspection),
	}
}

type Inspect struct {
	inspections map[string]*internal.Inspection
}

func (i *Inspect) Inspect(p *policyv1.Policy) error {
	if p == nil {
		return fmt.Errorf("policy is nil")
	}

	id := namer.PolicyKey(p)
	conditions, err := i.inspectConditions(p)
	if err != nil {
		return fmt.Errorf("failed to inspect conditions of the policy %s: %w", id, err)
	}

	i.inspections[id] = &internal.Inspection{
		Actions:    policy.ListActions(p),
		Conditions: conditions,
		Imports:    i.inspectImports(p),
		Variables:  policy.ListVariables(p),
	}

	return nil
}

func (i *Inspect) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	results := make(map[string]*responsev1.InspectPoliciesResponse_Result)
	referencedVariablesInEV := make(map[string]map[string]struct{})
	for policyID, ins := range i.inspections {
		if strings.HasPrefix(policyID, "export_variables") {
			if len(ins.Variables) > 0 {
				sort.Slice(ins.Variables, func(i, j int) bool {
					return ins.Variables[i].Name < ins.Variables[j].Name
				})

				results[policyID] = &responsev1.InspectPoliciesResponse_Result{
					Variables: ins.Variables,
				}
			}

			continue
		}

		varMap := make(map[string]*responsev1.InspectPoliciesResponse_Variable)
		for _, c := range ins.Conditions {
			for _, varName := range c.VarNames {
				for _, localVar := range ins.Variables {
					if varName == localVar.Name {
						if _, ok := varMap[varName]; !ok {
							varMap[varName] = localVar
						}
					}
				}

				for _, importedPolicyID := range ins.Imports {
					importedIns, ok := i.inspections[importedPolicyID]
					if !ok {
						return nil, fmt.Errorf("failed to find imported policy %s", importedPolicyID)
					}

					for _, importedVar := range importedIns.Variables {
						if varName == importedVar.Name {
							if _, ok := varMap[varName]; !ok {
								varMap[varName] = &responsev1.InspectPoliciesResponse_Variable{
									Name:   varName,
									Value:  importedVar.Value,
									Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_IMPORTED,
									Source: importedPolicyID,
								}

								if _, ok := referencedVariablesInEV[importedPolicyID]; !ok {
									referencedVariablesInEV[importedPolicyID] = make(map[string]struct{})
								}
								referencedVariablesInEV[importedPolicyID][varName] = struct{}{}
							}
						}
					}
				}
			}
		}

		if len(ins.Actions) == 0 && len(varMap) == 0 {
			continue
		}

		variables := make([]*responsev1.InspectPoliciesResponse_Variable, 0, len(varMap))
		for _, variable := range varMap {
			variables = append(variables, variable)
		}

		sort.Strings(ins.Actions)
		sort.Slice(variables, func(i, j int) bool {
			return variables[i].Name < variables[j].Name
		})

		results[policyID] = &responsev1.InspectPoliciesResponse_Result{
			Actions:   ins.Actions,
			Variables: variables,
		}
	}

	for policyID, referencedVars := range referencedVariablesInEV {
		result, ok := results[policyID]
		if !ok {
			return nil, fmt.Errorf("failed to find export variables policy %s ", policyID)
		}

		var variables []*responsev1.InspectPoliciesResponse_Variable
		for _, variable := range result.Variables {
			if _, ok := referencedVars[variable.Name]; ok {
				variables = append(variables, variable)
			}
		}

		if len(variables) == 0 {
			delete(results, policyID)
		} else {
			results[policyID].Variables = variables
		}
	}

	return results, nil
}

// inspectImports inspects the export variables imports of the policy.
func (i *Inspect) inspectImports(p *policyv1.Policy) []string {
	var imports []string
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		if pt.DerivedRoles.Variables == nil {
			return nil
		}

		for _, variablesName := range pt.DerivedRoles.Variables.Import {
			policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
			imports = append(imports, policyID)
		}
	case *policyv1.Policy_PrincipalPolicy:
		if pt.PrincipalPolicy.Variables == nil {
			return nil
		}

		for _, variablesName := range pt.PrincipalPolicy.Variables.Import {
			policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
			imports = append(imports, policyID)
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
func (i *Inspect) inspectConditions(p *policyv1.Policy) ([]*internal.Condition, error) {
	var conditions []*internal.Condition
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		for _, def := range pt.DerivedRoles.Definitions {
			if def.Condition == nil {
				continue
			}

			c, err := compile.Condition(def.Condition)
			if err != nil {
				return nil, fmt.Errorf("failed to compile condition: %w", err)
			}

			referencedVariableNames, err := i.referencedVariableNamesInCondition(c)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
			}

			var varNames []string
			for referencedVariableName := range referencedVariableNames {
				varNames = append(varNames, referencedVariableName)
			}

			conditions = append(conditions, &internal.Condition{
				Name:     def.Name,
				VarNames: varNames,
			})
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, rule := range pt.PrincipalPolicy.Rules {
			for _, action := range rule.Actions {
				if action.Condition == nil {
					continue
				}

				c, err := compile.Condition(action.Condition)
				if err != nil {
					return nil, fmt.Errorf("failed to compile condition: %w", err)
				}

				referencedVariableNames, err := i.referencedVariableNamesInCondition(c)
				if err != nil {
					return nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
				}

				var varNames []string
				for referencedVariableName := range referencedVariableNames {
					varNames = append(varNames, referencedVariableName)
				}

				conditions = append(conditions, &internal.Condition{
					Name:     action.Name,
					VarNames: varNames,
				})
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		for _, rule := range pt.ResourcePolicy.Rules {
			if rule.Condition == nil {
				continue
			}

			c, err := compile.Condition(rule.Condition)
			if err != nil {
				return nil, fmt.Errorf("failed to compile condition: %w", err)
			}

			referencedVariableNames, err := i.referencedVariableNamesInCondition(c)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in condition: %w", err)
			}

			var varNames []string
			for referencedVariableName := range referencedVariableNames {
				varNames = append(varNames, referencedVariableName)
			}

			conditions = append(conditions, &internal.Condition{
				Name:     rule.Name,
				VarNames: varNames,
			})
		}
	}

	return conditions, nil
}

func (i *Inspect) referencedVariableNamesInCondition(condition *runtimev1.Condition) (map[string]struct{}, error) {
	referencedVariableNames := make(map[string]struct{})
	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		for _, condition := range op.All.Expr {
			referenced, err := i.referencedVariableNamesInCondition(condition)
			if err != nil {
				return nil, fmt.Errorf("failed to find referenced variable names in all condition: %w", err)
			}

			for varName := range referenced {
				referencedVariableNames[varName] = struct{}{}
			}
		}
	case *runtimev1.Condition_Any:
		for _, condition := range op.Any.Expr {
			referenced, err := i.referencedVariableNamesInCondition(condition)
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
			referenced, err := i.referencedVariableNamesInCondition(condition)
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
