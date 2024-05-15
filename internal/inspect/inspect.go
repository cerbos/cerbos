// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/inspect/policy"
	"github.com/cerbos/cerbos/internal/inspect/policyset"
)

type Inspect[T policyv1.Policy | runtimev1.RunnablePolicySet] interface {
	// Results returns the final result after all processing is done
	Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error)
	// Inspect inspects the given policy and records the related information
	Inspect(*T) error
	// MissingImports returns the list of exportVariables not present in the inspected policy list
	MissingImports() []string
}

func PolicySets() Inspect[runtimev1.RunnablePolicySet] {
	return policyset.New()
}

func Policies() Inspect[policyv1.Policy] {
	return policy.New()
}
