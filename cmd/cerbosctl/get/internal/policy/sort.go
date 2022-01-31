// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	gosort "sort"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
)

func sort(pairs []KeyPolicyPair, sortBy flagset.SortByValue) []KeyPolicyPair {
	switch sortBy {
	case flagset.SortByPolicyID:
		gosort.SliceStable(pairs, func(i, j int) bool {
			return pairs[i].Key < pairs[j].Key
		})
	case flagset.SortByName:
		gosort.SliceStable(pairs, func(i, j int) bool {
			return pairs[i].Policy.Name < pairs[j].Policy.Name
		})
	case flagset.SortByVersion:
		gosort.SliceStable(pairs, func(i, j int) bool {
			return pairs[i].Policy.Version < pairs[j].Policy.Version
		})
	}

	return pairs
}
