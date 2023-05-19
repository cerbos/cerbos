// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCloneResult(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	is := require.New(t)
	ctx := context.Background()
	dir := t.TempDir()
	bucket := newMinioBucket(ctx, t, "policies")
	cloner, err := NewCloner(bucket, storeFS{dir})
	is.NoError(err)
	result, err := cloner.Clone(ctx)
	is.NoError(err)
	is.Equal([]string{
		"_schemas/principal.json",
		"_schemas/resources/leave_request.json",
		"_schemas/resources/purchase_order.json",
		"_schemas/resources/salary_record.json",
		"derived_roles/common_roles.yaml",
		"derived_roles/derived_roles_01.yaml",
		"derived_roles/derived_roles_02.yaml",
		"derived_roles/derived_roles_03.yaml",
		"principal_policies/policy_01.yaml",
		"principal_policies/policy_02.yaml",
		"principal_policies/policy_02_acme.hr.yaml",
		"principal_policies/policy_02_acme.yaml",
		"principal_policies/policy_03.yaml",
		"principal_policies/policy_04.yaml",
		"resource_policies/disabled_policy_01.yaml",
		"resource_policies/policy_01.yaml",
		"resource_policies/policy_02.yaml",
		"resource_policies/policy_03.yaml",
		"resource_policies/policy_04.yaml",
		"resource_policies/policy_05.yaml",
		"resource_policies/policy_05_acme.hr.uk.yaml",
		"resource_policies/policy_05_acme.hr.yaml",
		"resource_policies/policy_05_acme.yaml",
		"resource_policies/policy_06.yaml",
		"resource_policies/policy_07.yaml",
		"resource_policies/policy_08.yaml",
	}, result.updateOrAdd)
}
