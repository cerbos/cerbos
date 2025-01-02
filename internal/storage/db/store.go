// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"fmt"
	"strings"
)

type ErrBreaksScopeChain struct {
	PolicyKeys []string
}

func (e ErrBreaksScopeChain) Error() string {
	return fmt.Sprintf("removing the following scoped policies will break the scope chain: %s", strings.Join(e.PolicyKeys, ", "))
}
