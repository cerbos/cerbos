// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policyset

import (
	"fmt"
	"sort"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func New() *Inspect {
	return &Inspect{
		results: make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}
}

type Inspect struct {
	results map[string]*responsev1.InspectPoliciesResponse_Result
}

func (i *Inspect) Inspect(pset *runtimev1.RunnablePolicySet) error {
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

	if len(actions) > 0 || len(variables) > 0 {
		i.results[namer.PolicyKeyFromFQN(pset.Fqn)] = &responsev1.InspectPoliciesResponse_Result{
			Actions:   actions,
			Variables: variables,
		}
	}

	return nil
}

func (i *Inspect) MissingImports() []string {
	return nil
}

func (i *Inspect) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return i.results, nil
}
