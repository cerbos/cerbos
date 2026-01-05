// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

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
	exportConstantsNameFmt   = "my_constants_%d"
	exportVariablesNameFmt   = "my_variables_%d"
	principalPoliciesNameFmt = "donald_duck_%d"
	resourcePoliciesNameFmt  = "leave_request_%d"
	derivedRolesFmt          = "derived_roles.my_derived_roles_%d"
	exportConstantsFmt       = "export_constants.my_constants_%d"
	exportVariablesFmt       = "export_variables.my_variables_%d"
	principalPoliciesFmt     = "principal.donald_duck_%d.version"
	resourcePoliciesFmt      = "resource.leave_request_%d.default"
	version                  = "default"
)

func TestFilter(t *testing.T) {
	noOfPolicies := 2
	derivedRoles := mkDerivedRolesForFilter(t, noOfPolicies)
	exportConstants := mkExportConstantsForFilter(t, noOfPolicies)
	exportVariables := mkExportVariablesForFilter(t, noOfPolicies)
	principalPolicies := mkPrincipalPoliciesForFilter(t, noOfPolicies)
	resourcePolicies := mkResourcePoliciesForFilter(t, noOfPolicies)

	t.Run("should fail when filtering wrong kind of policies", func(t *testing.T) {
		require.Empty(t, filter(derivedRoles, nil, nil, policy.ExportConstantsKind))
		require.Empty(t, filter(derivedRoles, nil, nil, policy.ExportVariablesKind))
		require.Empty(t, filter(derivedRoles, nil, nil, policy.PrincipalKind))
		require.Empty(t, filter(derivedRoles, nil, nil, policy.ResourceKind))

		require.Empty(t, filter(exportConstants, nil, nil, policy.DerivedRolesKind))
		require.Empty(t, filter(exportConstants, nil, nil, policy.ExportVariablesKind))
		require.Empty(t, filter(exportConstants, nil, nil, policy.PrincipalKind))
		require.Empty(t, filter(exportConstants, nil, nil, policy.ResourceKind))

		require.Empty(t, filter(exportVariables, nil, nil, policy.DerivedRolesKind))
		require.Empty(t, filter(exportVariables, nil, nil, policy.ExportConstantsKind))
		require.Empty(t, filter(exportVariables, nil, nil, policy.PrincipalKind))
		require.Empty(t, filter(exportVariables, nil, nil, policy.ResourceKind))

		require.Empty(t, filter(principalPolicies, nil, nil, policy.DerivedRolesKind))
		require.Empty(t, filter(principalPolicies, nil, nil, policy.ExportConstantsKind))
		require.Empty(t, filter(principalPolicies, nil, nil, policy.ExportVariablesKind))
		require.Empty(t, filter(principalPolicies, nil, nil, policy.ResourceKind))

		require.Empty(t, filter(resourcePolicies, nil, nil, policy.DerivedRolesKind))
		require.Empty(t, filter(resourcePolicies, nil, nil, policy.ExportConstantsKind))
		require.Empty(t, filter(resourcePolicies, nil, nil, policy.ExportVariablesKind))
		require.Empty(t, filter(resourcePolicies, nil, nil, policy.PrincipalKind))
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

	// Export Constants
	t.Run("should filter export_constants by kind", func(t *testing.T) {
		filtered := filter(exportConstants, nil, nil, policy.ExportConstantsKind)
		require.Len(t, filtered, noOfPolicies)
	})

	t.Run("should filter export_constants by name", func(t *testing.T) {
		filtered := filter(exportConstants, []string{fmt.Sprintf(exportConstantsNameFmt, 1)}, nil, policy.ExportConstantsKind)
		require.Len(t, filtered, 1)
		require.Equal(t, fmt.Sprintf(exportConstantsNameFmt, 1), filtered[0].Name)
	})

	// Export Variables
	t.Run("should filter export_variables by kind", func(t *testing.T) {
		filtered := filter(exportVariables, nil, nil, policy.ExportVariablesKind)
		require.Len(t, filtered, noOfPolicies)
	})

	t.Run("should filter export_variables by name", func(t *testing.T) {
		filtered := filter(exportVariables, []string{fmt.Sprintf(exportVariablesNameFmt, 1)}, nil, policy.ExportVariablesKind)
		require.Len(t, filtered, 1)
		require.Equal(t, fmt.Sprintf(exportVariablesNameFmt, 1), filtered[0].Name)
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

func filter(policies []policy.Wrapper, names, versions []string, kind policy.Kind) []policy.Wrapper {
	fd := newFilterDef(kind, names, versions, true)
	filtered := make([]policy.Wrapper, 0, len(policies))
	for _, p := range policies {
		if fd.filter(p) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func mkDerivedRolesForFilter(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies - 1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenDerivedRoles(test.Suffix(strconv.Itoa(i))), fmt.Sprintf(derivedRolesFmt, i)))
	}
	return policies
}

func mkExportConstantsForFilter(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies - 1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenExportConstants(test.Suffix(strconv.Itoa(i))), fmt.Sprintf(exportConstantsFmt, i)))
	}
	return policies
}

func mkExportVariablesForFilter(t *testing.T, noOfPolicies int) []policy.Wrapper {
	t.Helper()

	policies := make([]policy.Wrapper, noOfPolicies)
	for i := noOfPolicies - 1; i >= 0; i-- {
		policies[i] = policy.Wrap(policy.WithStoreIdentifier(test.GenExportVariables(test.Suffix(strconv.Itoa(i))), fmt.Sprintf(exportVariablesFmt, i)))
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
