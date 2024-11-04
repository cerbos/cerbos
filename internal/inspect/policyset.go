// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
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

	attributes, err := ps.listReferencedAttributes(pset)
	if err != nil {
		return fmt.Errorf("failed to list referenced attributes in the policyset: %w", err)
	}

	policyKey := namer.PolicyKeyFromFQN(pset.Fqn)
	ps.results[policyKey] = &responsev1.InspectPoliciesResponse_Result{
		Actions:      policy.ListPolicySetActions(pset),
		Attributes:   attributes,
		Constants:    policy.ListPolicySetConstants(pset),
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
	attrs := make(map[string]*responsev1.InspectPoliciesResponse_Attribute)
	if err := visitCompiledPolicySet(pset, attributeVisitor(attrs)); err != nil {
		return nil, err
	}
	return attributeList(attrs), nil
}
