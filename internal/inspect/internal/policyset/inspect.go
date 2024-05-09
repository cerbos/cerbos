// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policyset

import (
	"fmt"
	"sort"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
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

func (i *Inspect) Inspect(pset *runtimev1.RunnablePolicySet) error {
	if pset == nil {
		return fmt.Errorf("policy set is nil")
	}

	i.inspections[namer.PolicyKeyFromFQN(pset.Fqn)] = &internal.Inspection{
		Actions:   policy.ListPolicySetActions(pset),
		Variables: policy.ListPolicySetVariables(pset),
	}

	return nil
}

func (i *Inspect) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	results := make(map[string]*responsev1.InspectPoliciesResponse_Result)
	for policyID, ins := range i.inspections {
		if len(ins.Actions) != 0 || len(ins.Variables) != 0 {
			sort.Strings(ins.Actions)
			sort.Slice(ins.Variables, func(i, j int) bool {
				return sort.StringsAreSorted([]string{ins.Variables[i].Name, ins.Variables[j].Name})
			})

			results[policyID] = &responsev1.InspectPoliciesResponse_Result{
				Actions:   ins.Actions,
				Variables: ins.Variables,
			}
		}
	}

	return results, nil
}
