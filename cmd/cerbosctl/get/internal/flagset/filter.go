// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import (
	"fmt"

	"github.com/cerbos/cerbos/internal/policy"
)

type Filters struct {
	Name    []string `help:"Filter policies by name"`
	Version []string `help:"Filter policies by version"`
}

func (f Filters) Validate(kind policy.Kind, listing bool) error {
	if !listing && (len(f.Name) > 0 || len(f.Version) > 0) {
		return fmt.Errorf("--name and --version flags are only available when listing")
	}

	if kind == policy.DerivedRolesKind && len(f.Version) > 0 {
		return fmt.Errorf("--version flag is not available when listing derived roles")
	}

	return nil
}
