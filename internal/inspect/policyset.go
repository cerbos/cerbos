// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"cmp"
	"fmt"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"slices"
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

	attributes, err := ps.listReferencedAttributes(pset)
	if err != nil {
		return fmt.Errorf("failed to list referenced attributes in the policyset: %w", err)
	}

	policyKey := namer.PolicyKeyFromFQN(pset.Fqn)
	ps.results[policyKey] = &responsev1.InspectPoliciesResponse_Result{
		Actions:      policy.ListPolicySetActions(pset),
		Attributes:   attributes,
		DerivedRoles: policy.ListPolicySetDerivedRoles(pset),
		PolicyId:     policyKey,
		Variables:    policy.ListPolicySetVariables(pset),
	}

	return nil
}

// Results returns the final inspection results.
func (ps *PolicySet) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return ps.results, nil
}

// inspectDefinitionsAndRules inspects the definitions and rules in the given policy set to find references to the attributes.
func (ps *PolicySet) listReferencedAttributes(pset *runtimev1.RunnablePolicySet) ([]*responsev1.InspectPoliciesResponse_Attribute, error) {
	referencedAttributes := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	switch set := pset.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, p := range set.PrincipalPolicy.Policies {
			for _, rule := range p.ResourceRules {
				for _, actionRule := range rule.ActionRules {
					for _, variable := range p.OrderedVariables {
						if err := ps.referencedAttributesInExpr(variable.Expr.Original, referencedAttributes); err != nil {
							return nil, fmt.Errorf("failed to find referenced attributes in the principal policy variable: %w", err)
						}
					}

					if actionRule.Condition == nil {
						continue
					}

					if err := referencedAttributesInCompiledCondition(actionRule.Condition, referencedAttributes); err != nil {
						return nil, fmt.Errorf("failed to find referenced attributes in the compiled principal policy rule: %w", err)
					}
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

			for _, dr := range p.DerivedRoles {
				if dr.Condition == nil {
					continue
				}

				if err := referencedAttributesInCompiledCondition(dr.Condition, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the compiled derived roles definition: %w", err)
				}
			}

			for _, rule := range p.Rules {
				if rule.Condition == nil {
					continue
				}

				if err := referencedAttributesInCompiledCondition(rule.Condition, referencedAttributes); err != nil {
					return nil, fmt.Errorf("failed to find referenced attributes in the compiled resource policy rule: %w", err)
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

	if err := referencedAttributesInCompiledCondition(c, outAttr); err != nil {
		return fmt.Errorf("failed to find referenced attributes in the expression: %w", err)
	}

	return nil
}
