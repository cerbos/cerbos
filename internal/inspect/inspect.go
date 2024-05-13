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
	Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error)
	Inspect(*T) error
}

func PolicySets() Inspect[runtimev1.RunnablePolicySet] {
	return policyset.New()
}

func Policies() Inspect[policyv1.Policy] {
	return policy.New()
}
