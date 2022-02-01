// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"

	"github.com/cerbos/cerbos/internal/policy"
)

func stringInSlice(a string, s []string) bool {
	for _, b := range s {
		if strings.EqualFold(b, a) {
			return true
		}
	}
	return false
}

func filter(policies []policy.Wrapper, name, version []string, kind policy.Kind) []policy.Wrapper {
	filtered := make([]policy.Wrapper, 0, len(policies))
	for _, p := range policies {
		if len(name) != 0 && !stringInSlice(p.Name, name) {
			continue
		}
		if len(version) != 0 && !stringInSlice(p.Version, version) {
			continue
		}

		policyKind := policy.GetKind(p.Policy)
		if policyKind != kind {
			continue
		}

		filtered = append(filtered, p)
	}

	return filtered
}
