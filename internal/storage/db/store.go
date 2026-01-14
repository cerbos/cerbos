// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package db

import (
	"fmt"
	"strings"
)

type BreaksScopeChainErr struct {
	Policies map[string][]string
}

func (e BreaksScopeChainErr) Error() string {
	policyKeys := make([]string, len(e.Policies))
	i := 0
	for pk := range e.Policies {
		policyKeys[i] = pk
		i++
	}

	return fmt.Sprintf("removing the following scoped policies will break the scope chain: %s", strings.Join(policyKeys, ", "))
}

type RequiredByOtherPoliciesErr struct {
	Policies map[string][]string
}

func (e RequiredByOtherPoliciesErr) Error() string {
	policyKeys := make([]string, len(e.Policies))
	i := 0
	for pk := range e.Policies {
		policyKeys[i] = pk
		i++
	}

	return fmt.Sprintf("removing the following policies will break the dependent policies: %s", strings.Join(policyKeys, ", "))
}
