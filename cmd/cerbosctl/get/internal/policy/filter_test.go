// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package policy

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	derivedRolesNameFmt      = "my_derived_roles_%d"
	principalPoliciesNameFmt = "donald_duck_%d"
	resourcePoliciesNameFmt  = "leave_request_%d"
	derivedRolesFmt          = "derived_roles.my_derived_roles_%d"
	principalPoliciesFmt     = "principal.donald_duck_%d.version"
	resourcePoliciesFmt      = "resource.leave_request_%d.default"
	version                  = "default"
)

func TestFilter(t *testing.T) {
	noOfPolicies := 2
	derivedRoles := mkDerivedRolesForFilter(t, noOfPolicies)
	principalPolicies := mkPrincipalPoliciesForFilter(t, noOfPolicies)
	resourcePolicies := mkResourcePoliciesForFilter(t, noOfPolicies)

	t.Run("should fail when filtering wrong kind of policies", func(t *testing.T) {
		filtered := filter(derivedRoles, nil, nil, policy.PrincipalKind)
		require.Empty(t, filtered)
		filtered = filter(derivedRoles, nil, nil, policy.ResourceKind)
		require.Empty(t, filtered)

		filtered = filter(principalPolicies, nil, nil, policy.DerivedRolesKind)
		require.Empty(t, filtered)
		filtered = filter(principalPolicies, nil, nil, policy.ResourceKind)
		require.Empty(t, filtered)

		filtered = filter(resourcePolicies, nil, nil, policy.DerivedRolesKind)
		require.Empty(t, filtered)
		filtered = filter(resourcePolicies, nil, nil, policy.PrincipalKind)
		require.Empty(t, filtered)
	})

	// Derived Roles
	t.Run("should filter derived_roles by kind", func(t *testing.T) {
		filtered := filter(derivedRoles, nil, nil, policy.DerivedRolesKind)
		require.Len(t, filtered, noOfPolicies)
	})

	t.Run("should filter derived_roles by name", func(t *testing.T) {
		filtered := filter(derivedRoles, []string{fmt.Sprintf(derivedRolesNameFmt, 1)}, nil, policy.DerivedRolesKind)
		require.Len(t, filtered, 1)
		require.Equal(t, fmt.Sprintf(derivedRolesNameFmt, 1), filtered[0].Name)
	})

	// Principal Policies
	t.Run("should filter principal_policies by kind", func(t *testing.T) {
		filtered := filter(principalPolicies, nil, nil, policy.PrincipalKind)
		require.Len(t, filtered, noOfPolicies)
	})

	t.Run("should filter principal_policies by name", func(t *testing.T) {
		filtered := filter(principalPolicies, []string{fmt.Sprintf(principalPoliciesNameFmt, 1)}, nil, policy.PrincipalKind)
		require.Len(t, filtered, 1)
		require.Equal(t, fmt.Sprintf(principalPoliciesNameFmt, 1), filtered[0].Name)
	})

	t.Run("should filter principal_policies by version", func(t *testing.T) {
		filtered := filter(principalPolicies, nil, []string{version}, policy.PrincipalKind)
		require.Len(t, filtered, noOfPolicies)
		require.Equal(t, version, filtered[0].Version)
	})

	// Resource Policies
	t.Run("should filter resource_policies by kind", func(t *testing.T) {
		filtered := filter(resourcePolicies, nil, nil, policy.ResourceKind)
		require.Len(t, filtered, noOfPolicies)
	})

	t.Run("should filter resource_policies by name", func(t *testing.T) {
		filtered := filter(resourcePolicies, []string{fmt.Sprintf(resourcePoliciesNameFmt, 1)}, nil, policy.ResourceKind)
		require.Len(t, filtered, 1)
		require.Equal(t, fmt.Sprintf(resourcePoliciesNameFmt, 1), filtered[0].Name)
	})

	t.Run("should filter resource_policies by version", func(t *testing.T) {
		filtered := filter(resourcePolicies, nil, []string{version}, policy.ResourceKind)
		require.Len(t, filtered, noOfPolicies)
		require.Equal(t, version, filtered[0].Version)
	})
}

func mkDerivedRolesForFilter(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies - 1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenDerivedRoles(test.Suffix(strconv.Itoa(i))), fmt.Sprintf(derivedRolesFmt, i)))
	}
	return policies
}

func mkPrincipalPoliciesForFilter(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies - 1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenPrincipalPolicy(test.Suffix(strconv.Itoa(i))), fmt.Sprintf(principalPoliciesFmt, i)))
	}
	return policies
}

func mkResourcePoliciesForFilter(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies - 1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenResourcePolicy(test.Suffix(strconv.Itoa(i))), fmt.Sprintf(resourcePoliciesFmt, i)))
	}
	return policies
}
