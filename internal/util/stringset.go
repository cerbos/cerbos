// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

func ToStringSet(values []string) StringSet {
	ss := make(StringSet)
	for _, v := range values {
		ss[v] = struct{}{}
	}

	return ss
}

type StringSet map[string]struct{}

func (ss StringSet) Contains(value string) bool {
	_, exists := ss[value]
	return exists
}
