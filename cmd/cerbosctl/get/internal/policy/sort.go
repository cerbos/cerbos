// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	gosort "sort"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/internal/policy"
)

func sort(policies []policy.Wrapper, sortBy flagset.SortBy) []policy.Wrapper {
	switch sortBy {
	case flagset.SortByPolicyID, flagset.SortByNone:
		gosort.SliceStable(policies, func(i, j int) bool {
			return policies[i].Metadata.StoreIdentifier < policies[j].Metadata.StoreIdentifier
		})
	case flagset.SortByName:
		gosort.SliceStable(policies, func(i, j int) bool {
			return policies[i].Name < policies[j].Name
		})
	case flagset.SortByVersion:
		gosort.SliceStable(policies, func(i, j int) bool {
			return policies[i].Version < policies[j].Version
		})
	}

	return policies
}
