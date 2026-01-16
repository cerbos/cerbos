// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package db

import (
	"strings"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

type IntegrityErr struct {
	Errors map[string]*responsev1.IntegrityErrors
}

func (e *IntegrityErr) Error() string {
	policiesBreakingScopeChain := make([]string, 0, len(e.Errors))
	policiesRequiredByOtherPolicies := make([]string, 0, len(e.Errors))

	for policyKey, ie := range e.Errors {
		if ie.BreaksScopeChain != nil && len(ie.BreaksScopeChain.Descendants) > 0 {
			policiesBreakingScopeChain = append(policiesBreakingScopeChain, policyKey)
		}

		if ie.RequiredByOtherPolicies != nil && len(ie.RequiredByOtherPolicies.Dependents) > 0 {
			policiesRequiredByOtherPolicies = append(policiesRequiredByOtherPolicies, policyKey)
		}
	}

	sb := new(strings.Builder)
	sb.WriteString("cannot perform delete operation")
	if len(policiesBreakingScopeChain) > 0 {
		sb.WriteString(": breaks scope chains [")
		sb.WriteString(strings.Join(policiesBreakingScopeChain, ","))
		sb.WriteString("]")
	}

	if len(policiesRequiredByOtherPolicies) > 0 {
		sb.WriteString(": required by other policies [")
		sb.WriteString(strings.Join(policiesRequiredByOtherPolicies, ","))
		sb.WriteString("]")
	}

	return sb.String()
}
