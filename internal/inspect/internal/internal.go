// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"

type Condition struct {
	// Name denotes the action name (principal policy), definition name (derived roles) or the rule name (resource policy)
	Name string
	// VarNames are the variables referenced by this Condition
	VarNames []string
}

type Inspection struct {
	Actions    []string
	Conditions []*Condition
	// Imports is a list of imported exportVariables policies
	Imports   []string
	Variables []*responsev1.InspectPoliciesResponse_Variable
}
