// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"sort"

	v1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

func sortSchemas(schemasIds []string) {
	sort.Strings(schemasIds)
}

func sortPolicies(sortOptions *v1.ListPoliciesRequest_SortOptions, ids []string) {
	if sortOptions == nil {
		return
	}

	if sortOptions.Order == v1.ListPoliciesRequest_SortOptions_ORDER_DESCENDING {
		sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	} else {
		sort.Sort(sort.StringSlice(ids))
	}
}
