// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package db

import (
	"fmt"
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

	if len(policiesBreakingScopeChain) > 0 && len(policiesRequiredByOtherPolicies) > 0 {
		return fmt.Sprintf(
			"removing the scoped policies [%s] will break the scope chain(s) and removing the policies [%s] will break the dependent policies",
			strings.Join(policiesBreakingScopeChain, ", "),
			strings.Join(policiesRequiredByOtherPolicies, ", "),
		)
	} else if len(policiesBreakingScopeChain) != 0 {
		return fmt.Sprintf("removing the following scoped policies will break the scope chain: %s", strings.Join(policiesBreakingScopeChain, ", "))
	}

	return fmt.Sprintf("removing the following policies will break the dependent policies: %s", strings.Join(policiesRequiredByOtherPolicies, ", "))
}
