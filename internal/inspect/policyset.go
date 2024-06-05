// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"
	"sort"

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

	actions := policy.ListPolicySetActions(pset)
	if len(actions) > 0 {
		sort.Strings(actions)
	}

	variables := policy.ListPolicySetVariables(pset)
	if len(variables) > 0 {
		sort.Slice(variables, func(i, j int) bool {
			return sort.StringsAreSorted([]string{variables[i].Name, variables[j].Name})
		})
	}

	policyKey := namer.PolicyKeyFromFQN(pset.Fqn)
	ps.results[policyKey] = &responsev1.InspectPoliciesResponse_Result{
		Actions:         actions,
		Variables:       variables,
		StoreIdentifier: policyKey,
	}

	return nil
}

// Results returns the final inspection results.
func (ps *PolicySet) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return ps.results, nil
}
