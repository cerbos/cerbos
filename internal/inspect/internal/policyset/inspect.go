// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policyset

import (
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

func (i *Inspect) Inspect(pset *runtimev1.RunnablePolicySet) {
	result := &responsev1.InspectPoliciesResponse_Result{}
	actions := policy.ListPolicySetActions(pset)
	if len(actions) > 0 {
		result.Actions = actions
	}

	variables := policy.ListPolicySetVariables(pset)
	if len(variables) > 0 {
		result.Variables = variables
	}

	if len(actions) > 0 || len(variables) > 0 {
		i.results[namer.PolicyKeyFromFQN(pset.Fqn)] = result
	}
}

func (i *Inspect) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return i.results, nil
}
