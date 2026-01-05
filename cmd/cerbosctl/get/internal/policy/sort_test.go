// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package policy

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

func TestSort(t *testing.T) {
	t.Run("should sort by policyId", func(t *testing.T) {
		noOfPolicies := 3
		policies := mkPoliciesForSort(t, noOfPolicies)
		expected := make([]string, noOfPolicies)
		for i := range noOfPolicies {
			expected[i] = fmt.Sprintf(principalPoliciesFmt, i)
		}

		policies = sort(policies, flagset.SortByPolicyID)
		require.NotEmpty(t, policies)
		for idx, p := range policies {
			require.Equal(t, expected[idx], p.Metadata.StoreIdentifier)
		}
	})

	t.Run("should sort by name", func(t *testing.T) {
		noOfPolicies := 3
		policies := mkPoliciesForSort(t, noOfPolicies)
		expected := make([]string, noOfPolicies)
		for i := range noOfPolicies {
			expected[i] = fmt.Sprintf(principalPoliciesNameFmt, i)
		}

		policies = sort(policies, flagset.SortByName)
		require.NotEmpty(t, policies)
		for idx, p := range policies {
			require.Equal(t, expected[idx], p.Name)
		}
	})

	t.Run("should sort by version", func(t *testing.T) {
		noOfPolicies := 3
		policies := mkPoliciesForSortByVersion(t, noOfPolicies)

		policies = sort(policies, flagset.SortByVersion)
		require.NotEmpty(t, policies)
		for idx, p := range policies {
			require.Equal(t, fmt.Sprintf("default_%d", idx), p.Version)
		}
	})
}

func mkPoliciesForSort(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies - 1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(noOfPolicies-i-1))), fmt.Sprintf(principalPoliciesFmt, noOfPolicies-i-1)))
	}
	return policies
}

func mkPoliciesForSortByVersion(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := mkPoliciesForSort(t, noOfPolicies)
	for i := range noOfPolicies {
		policies[i].Version = fmt.Sprintf("%s_%d", policies[i].Version, noOfPolicies-i-1)
		policies[i].Policy = policy.WithStoreIdentifier(policies[i].Policy, fmt.Sprintf("%s_%d", policies[i].Metadata.StoreIdentifier, noOfPolicies-i-1))
	}
	return policies
}
