// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import (
	"fmt"

	"github.com/cerbos/cerbos/internal/policy"
)

//nolint:govet
type Filters struct {
	Name            []string `help:"Filter policies by name"`
	NameRegexp      string   `help:"Filter policies by name, using regular expression"`
	Version         []string `help:"Filter policies by version"`
	VersionRegexp   string   `help:"Filter policies by version, using regular expression"`
	PolicyIDs       []string `help:"List of policy ids" arg:"" name:"id" optional:"" `
	ScopeRegexp     string   `help:"Filter policies by scope, using regular expression"`
	IncludeDisabled bool     `help:"Include disabled policies"`
}

func (f Filters) Validate(kind policy.Kind, listing bool) error {
	if !listing && (len(f.Name) > 0 || len(f.Version) > 0) {
		return fmt.Errorf("--name and --version flags are only available when listing")
	}

	if !listing && (f.NameRegexp != "" || f.VersionRegexp != "" || f.ScopeRegexp != "") {
		return fmt.Errorf("--{name|version|scope}-regexp flags are only available when listing")
	}

	if len(f.Name) > 0 && f.NameRegexp != "" {
		return fmt.Errorf("--name and --name-regexp flags cannot be used together")
	}

	if len(f.Version) > 0 && f.VersionRegexp != "" {
		return fmt.Errorf("--version and --version-regexp flags cannot be used together")
	}

	switch kind { //nolint:exhaustive
	case policy.DerivedRolesKind:
		if f.ScopeRegexp != "" {
			return fmt.Errorf("--scope-regexp flag is not available when listing derived roles")
		}

		if len(f.Version) > 0 {
			return fmt.Errorf("--version flag is not available when listing derived roles")
		}

		if f.VersionRegexp != "" {
			return fmt.Errorf("--version-regexp flag is not available when listing derived roles")
		}

	case policy.ExportConstantsKind:
		if f.ScopeRegexp != "" {
			return fmt.Errorf("--scope-regexp flag is not available when listing exported constants")
		}

		if len(f.Version) > 0 {
			return fmt.Errorf("--version flag is not available when listing exported constants")
		}

		if f.VersionRegexp != "" {
			return fmt.Errorf("--version-regexp flag is not available when listing exported constants")
		}

	case policy.ExportVariablesKind:
		if f.ScopeRegexp != "" {
			return fmt.Errorf("--scope-regexp flag is not available when listing exported variables")
		}

		if len(f.Version) > 0 {
			return fmt.Errorf("--version flag is not available when listing exported variables")
		}

		if f.VersionRegexp != "" {
			return fmt.Errorf("--version-regexp flag is not available when listing exported variables")
		}

	case policy.RolePolicyKind:
		if len(f.Version) > 0 {
			return fmt.Errorf("--version flag is not available when listing role policies")
		}

		if f.VersionRegexp != "" {
			return fmt.Errorf("--version-regexp flag is not available when listing role policies")
		}
	}

	return nil
}
