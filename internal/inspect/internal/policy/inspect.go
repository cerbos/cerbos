// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func New() *Inspect {
	return &Inspect{
		results:      make(map[string]*responsev1.InspectPoliciesResponse_Result),
		resolveLater: make(map[string]string),
	}
}

type Inspect struct {
	results      map[string]*responsev1.InspectPoliciesResponse_Result
	resolveLater map[string]string
}

func (i *Inspect) Inspect(p *policyv1.Policy) {
	actions := policy.ListActions(p)
	variables := policy.ListVariables(p)
	variables = append(variables, i.resolveImportedVariables(p)...)
	i.results[namer.PolicyKey(p)] = &responsev1.InspectPoliciesResponse_Result{
		Actions:   actions,
		Variables: variables,
	}
}

func (i *Inspect) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	for policyID, importedPolicyID := range i.resolveLater {
		if _, ok := i.results[policyID]; !ok {
			return nil, fmt.Errorf("failed to find policy %s", policyID)
		}

		importedResult, ok := i.results[importedPolicyID]
		if !ok {
			return nil, fmt.Errorf("failed to find imported policy %s", importedPolicyID)
		}

		if importedResult != nil {
			for _, variable := range importedResult.Variables {
				i.results[policyID].Variables = append(i.results[policyID].Variables, &responsev1.InspectPoliciesResponse_Variable{
					Name:  variable.Name,
					Value: variable.Value,
					Source: &responsev1.InspectPoliciesResponse_Variable_Source{
						Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
						Id:   importedPolicyID,
					},
				})
			}
		}
	}

	return i.results, nil
}

func (i *Inspect) resolveImportedVariables(p *policyv1.Policy) []*responsev1.InspectPoliciesResponse_Variable {
	var variables []*responsev1.InspectPoliciesResponse_Variable
	if p == nil {
		return variables
	}

	id := namer.PolicyKey(p)
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		if pt.DerivedRoles.Variables == nil {
			return variables
		}

		for _, variablesName := range pt.DerivedRoles.Variables.Import {
			policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
			if r, ok := i.results[policyID]; ok {
				if r != nil {
					for _, v := range r.Variables {
						variables = append(variables, &responsev1.InspectPoliciesResponse_Variable{
							Name:  v.Name,
							Value: v.Value,
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
								Id:   policyID,
							},
						})
					}
				}
			} else {
				i.resolveLater[id] = policyID
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		if pt.PrincipalPolicy.Variables == nil {
			return variables
		}

		for _, variablesName := range pt.PrincipalPolicy.Variables.Import {
			policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
			if r, ok := i.results[policyID]; ok {
				if r != nil {
					for _, v := range r.Variables {
						variables = append(variables, &responsev1.InspectPoliciesResponse_Variable{
							Name:  v.Name,
							Value: v.Value,
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
								Id:   policyID,
							},
						})
					}
				}
			} else {
				i.resolveLater[id] = policyID
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		if pt.ResourcePolicy.Variables == nil {
			return variables
		}

		for _, variablesName := range pt.ResourcePolicy.Variables.Import {
			policyID := namer.PolicyKeyFromFQN(namer.ExportVariablesFQN(variablesName))
			if r, ok := i.results[policyID]; ok {
				if r != nil {
					for _, v := range r.Variables {
						variables = append(variables, &responsev1.InspectPoliciesResponse_Variable{
							Name:  v.Name,
							Value: v.Value,
							Source: &responsev1.InspectPoliciesResponse_Variable_Source{
								Type: responsev1.InspectPoliciesResponse_Variable_Source_TYPE_IMPORTED,
								Id:   policyID,
							},
						})
					}
				}
			} else {
				i.resolveLater[id] = policyID
			}
		}
	}

	return variables
}
