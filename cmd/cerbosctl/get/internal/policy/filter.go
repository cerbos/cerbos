// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func stringInSlice(a string, s []string) bool {
	for _, b := range s {
		if strings.EqualFold(b, a) {
			return true
		}
	}
	return false
}

func filter(keyPolicyPairs []KeyPolicyPair, name, version []string, resType ResourceType) []KeyPolicyPair {
	filtered := make([]KeyPolicyPair, 0, len(keyPolicyPairs))
	for _, pair := range keyPolicyPairs {
		if len(name) != 0 && !stringInSlice(pair.Policy.Name, name) {
			continue
		}
		if len(version) != 0 && !stringInSlice(pair.Policy.Version, version) {
			continue
		}

		_, ok := pair.Policy.PolicyType.(*policyv1.Policy_ResourcePolicy)
		if ok && resType != ResourcePolicy {
			continue
		}
		_, ok = pair.Policy.PolicyType.(*policyv1.Policy_PrincipalPolicy)
		if ok && resType != PrincipalPolicy {
			continue
		}
		_, ok = pair.Policy.PolicyType.(*policyv1.Policy_DerivedRoles)
		if ok && resType != DerivedRoles {
			continue
		}

		filtered = append(filtered, pair)
	}

	return filtered
}
