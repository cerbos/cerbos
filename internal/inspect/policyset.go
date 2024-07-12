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
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func PolicySets() *PolicySet {
	return &PolicySet{
		results: make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}
}

type PolicySet struct {
	results map[string]*responsev1.InspectPoliciesResponse_Result
}

// Inspect inspects the given policy set and caches the inspection related information internally.
func (ps *PolicySet) Inspect(pset *runtimev1.RunnablePolicySet) error {
	if pset == nil {
		return fmt.Errorf("policy set is nil")
	}

	actions := policy.ListPolicySetActions(pset)
	if len(actions) > 0 {
		sort.Strings(actions)
	}

	referencedAttributes, err := ps.inspectDefinitionsAndRules(pset)
	if err != nil {
		return fmt.Errorf("failed to inspect definitions and rules of the policyset: %w", err)
	}

	referencedAttributesFromVariables, err := ps.inspectVariableDefinitions(pset)
	if err != nil {
		return fmt.Errorf("failed to inspect variable definitions of the policyset: %w", err)
	}

	for name, attr := range referencedAttributesFromVariables {
		referencedAttributes[name] = &responsev1.InspectPoliciesResponse_Attribute{
			Name: attr.Name,
			Type: attr.Type,
		}
	}

	attributes := make([]*responsev1.InspectPoliciesResponse_Attribute, 0, len(referencedAttributes))
	for _, attr := range referencedAttributes {
		attributes = append(attributes, &responsev1.InspectPoliciesResponse_Attribute{
			Name: attr.Name,
			Type: attr.Type,
		})
	}
	if len(attributes) > 0 {
		sort.Slice(attributes, func(i, j int) bool {
			return sort.StringsAreSorted([]string{attributes[i].Name, attributes[j].Name})
		})
	}

	derivedRoles := policy.ListPolicySetDerivedRoles(pset)
	if len(derivedRoles) > 0 {
		sort.Slice(derivedRoles, func(i, j int) bool {
			return sort.StringsAreSorted([]string{derivedRoles[i].Name, derivedRoles[j].Name})
		})
	}

	variables := policy.ListPolicySetVariables(pset)
	if len(variables) > 0 {
		sort.Slice(variables, func(i, j int) bool {
			return sort.StringsAreSorted([]string{variables[i].Name, variables[j].Name})
		})
	}

	policyKey := namer.PolicyKeyFromFQN(pset.Fqn)
	ps.results[policyKey] = &responsev1.InspectPoliciesResponse_Result{
		Actions:      actions,
		Attributes:   attributes,
		DerivedRoles: derivedRoles,
		PolicyId:     policyKey,
		Variables:    variables,
	}

	return nil
}

// Results returns the final inspection results.
func (ps *PolicySet) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return ps.results, nil
}

// inspectDefinitionsAndRules inspects the definitions and rules in the given policy set to find references to the attributes.
func (ps *PolicySet) inspectDefinitionsAndRules(pset *runtimev1.RunnablePolicySet) (referencedAttributes map[string]*responsev1.InspectPoliciesResponse_Attribute, err error) {
	referencedAttributes = make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	switch set := pset.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, p := range set.PrincipalPolicy.Policies {
			for _, rule := range p.ResourceRules {
				for _, actionRule := range rule.ActionRules {
					if actionRule.Condition == nil {
						continue
					}

					if err := ps.referencedAttributesInCompiledCondition(actionRule.Condition, referencedAttributes); err != nil {
						return nil, fmt.Errorf("failed to find referenced attributes in the compiled principal policy rule: %w", err)
					}
				}
			}
		}
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		for _, p := range set.ResourcePolicy.Policies {
			for _, dr := range p.DerivedRoles {
				if dr.Condition == nil {
					continue
				}

				if err := ps.referencedAttributesInCompiledCondition(dr.Condition, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the compiled derived roles definition: %w", err)
				}
			}

			for _, rule := range p.Rules {
				if rule.Condition == nil {
					continue
				}

				if err := ps.referencedAttributesInCompiledCondition(rule.Condition, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the compiled resource policy rule: %w", err)
				}
			}
		}
	}

	return referencedAttributes, nil
}

// inspectVariableDefinitions inspects the variable values to find references to the attributes.
func (ps *PolicySet) inspectVariableDefinitions(pset *runtimev1.RunnablePolicySet) (referencedAttributes map[string]*responsev1.InspectPoliciesResponse_Attribute, err error) {
	referencedAttributes = make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	switch set := pset.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, p := range set.PrincipalPolicy.Policies {
			for _, variable := range p.OrderedVariables {
				if err := ps.referencedAttributesInExpr(variable.Expr.Original, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the principal policy variable: %w", err)
				}
			}
		}
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		for _, p := range set.ResourcePolicy.Policies {
			for _, variable := range p.OrderedVariables {
				if err := ps.referencedAttributesInExpr(variable.Expr.Original, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the resource policy variable: %w", err)
				}
			}
		}
	}

	return referencedAttributes, nil
}

func (ps *PolicySet) referencedAttributesInExpr(expr string, outAttr map[string]*responsev1.InspectPoliciesResponse_Attribute) error {
	c, err := compile.Condition(&policyv1.Condition{
		Condition: &policyv1.Condition_Match{
			Match: &policyv1.Match{
				Op: &policyv1.Match_Expr{
					Expr: expr,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to compile the condition: %w", err)
	}

	if err := ps.referencedAttributesInCompiledCondition(c, outAttr); err != nil {
		return fmt.Errorf("failed to find referenced attributes in the expression: %w", err)
	}

	return nil
}

func (ps *PolicySet) referencedAttributesInCompiledCondition(condition *runtimev1.Condition, outAttr map[string]*responsev1.InspectPoliciesResponse_Attribute) error {
	switch op := condition.Op.(type) {
	case *runtimev1.Condition_All:
		for _, condition := range op.All.Expr {
			if err := ps.referencedAttributesInCompiledCondition(condition, outAttr); err != nil {
				return fmt.Errorf("failed to find referenced attributes in the 'all' expression: %w", err)
			}
		}
	case *runtimev1.Condition_Any:
		for _, condition := range op.Any.Expr {
			if err := ps.referencedAttributesInCompiledCondition(condition, outAttr); err != nil {
				return fmt.Errorf("failed to find referenced attributes in the 'any' expression: %w", err)
			}
		}
	case *runtimev1.Condition_Expr:
		exprAST, err := ast.ToAST(op.Expr.Checked)
		if err != nil {
			return fmt.Errorf("failed to convert checked expression %s to AST: %w", op.Expr.Checked, err)
		}

		setAttr := func(name string, t responsev1.InspectPoliciesResponse_Attribute_Type) {
			if outAttr == nil {
				return
			}

			switch t {
			case responsev1.InspectPoliciesResponse_Attribute_TYPE_PRINCIPAL_ATTRIBUTE:
				outAttr[fmt.Sprintf("%s|%s", conditions.CELPrincipalAbbrev, name)] = &responsev1.InspectPoliciesResponse_Attribute{
					Name: name,
					Type: t,
				}
			case responsev1.InspectPoliciesResponse_Attribute_TYPE_RESOURCE_ATTRIBUTE:
				outAttr[fmt.Sprintf("%s|%s", conditions.CELResourceAbbrev, name)] = &responsev1.InspectPoliciesResponse_Attribute{
					Name: name,
					Type: t,
				}
			default:
			}
		}

		ast.PreOrderVisit(exprAST.Expr(), attributeAndVariableVisitor(setAttr, nil))
	case *runtimev1.Condition_None:
		for _, condition := range op.None.Expr {
			if err := ps.referencedAttributesInCompiledCondition(condition, outAttr); err != nil {
				return fmt.Errorf("failed to find referenced attributes in the 'none' expression: %w", err)
			}
		}
	}

	return nil
}
