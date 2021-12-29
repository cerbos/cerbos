// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"sort"
)

func sortSchemas(schemasIds []string) {
	sort.Strings(schemasIds)
}

func sortPolicies(ids []string) {
	sort.Strings(ids)
}
