// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import (
	"fmt"

	"github.com/cerbos/cerbos/internal/policy"
)

type Sort struct {
	SortBy SortBy `help:"Sort policies by column" default:""`
}

func (s Sort) Validate(kind policy.Kind, listing bool) error {
	if !listing && s.SortBy != SortByNone {
		return fmt.Errorf("--sort-by flag is only available when listing")
	}

	if listing && kind == policy.DerivedRolesKind && s.SortBy == SortByVersion {
		return fmt.Errorf("value of --sort-by flag cannot be %q when listing derived_roles", SortByVersion)
	}

	return nil
}

type SortBy string

const (
	SortByNone     SortBy = ""
	SortByPolicyID SortBy = "policyId"
	SortByName     SortBy = "name"
	SortByVersion  SortBy = "version"
)
