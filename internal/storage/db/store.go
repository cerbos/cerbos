// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package db

import (
	"fmt"
	"strings"
)

type BreaksScopeChainErr struct {
	PolicyKeys []string
}

func (e BreaksScopeChainErr) Error() string {
	return fmt.Sprintf("removing the following scoped policies will break the scope chain: %s", strings.Join(e.PolicyKeys, ", "))
}

type BreaksDependentsErr struct {
	PolicyKeys []string
}

func (e BreaksDependentsErr) Error() string {
	return fmt.Sprintf("removing the following policies will break the dependent policies: %s", strings.Join(e.PolicyKeys, ", "))
}
