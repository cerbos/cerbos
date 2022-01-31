// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"github.com/cerbos/cerbos/internal/policy"
	"strings"

)

func stringInSlice(a string, s []string) bool {
	for _, b := range s {
		if strings.EqualFold(b, a) {
			return true
		}
	}
	return false
}

func filter(keyPolicyPairs []KeyPolicyPair, name, version []string, kind policy.Kind) []KeyPolicyPair {
	filtered := make([]KeyPolicyPair, 0, len(keyPolicyPairs))
	for _, pair := range keyPolicyPairs {
		if len(name) != 0 && !stringInSlice(pair.Policy.Name, name) {
			continue
		}
		if len(version) != 0 && !stringInSlice(pair.Policy.Version, version) {
			continue
		}

		policyKind := policy.GetKind(pair.Policy.Policy)
		if policyKind != kind {
			continue
		}

		filtered = append(filtered, pair)
	}

	return filtered
}
