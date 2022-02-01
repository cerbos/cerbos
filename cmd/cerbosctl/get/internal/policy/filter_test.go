// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package policy

import (
	"fmt"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/stretchr/testify/require"
	"strconv"
	"testing"
)

const derivedRolesFmt = "derived_roles.my_derived_roles_%d"

func TestSort(t *testing.T) {
	t.Run("Sort by policyId", func(t *testing.T) {
		noOfPolicies := 3
		policies := mkPolicies(t, noOfPolicies)
		expected := make([]string, noOfPolicies)
		for i := 0; i < noOfPolicies; i++ {
			expected[i] = fmt.Sprintf(derivedRolesFmt, i)
		}

		sorted := sort(policies, flagset.SortByPolicyID)
		require.NotEmpty(t, sorted)
		for idx, p := range sorted {
			require.Equal(t, expected[idx], p.Metadata.StoreIdentifer)
		}
	})
}

func mkPolicies(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies-1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenDerivedRoles(test.Suffix(strconv.Itoa(i))), fmt.Sprintf(derivedRolesFmt, i)))
	}
	return policies
}