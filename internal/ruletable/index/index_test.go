// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index_test

import (
	"context"
	"testing"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/stretchr/testify/require"
)

func TestParentRoleIndex(t *testing.T) {
	ctx := context.Background()
	impl := index.NewImpl(index.NewMem())

	scopeParentRoles := map[string]*runtimev1.RuleTable_RoleParentRoles{
		"acme": {
			RoleParentRoles: map[string]*runtimev1.RuleTable_RoleParentRoles_ParentRoles{
				"manager": {
					Roles: []string{"employee"},
				},
				"employee": {
					Roles: []string{"user"},
				},
			},
		},
		"acme.hr": {
			RoleParentRoles: map[string]*runtimev1.RuleTable_RoleParentRoles_ParentRoles{
				"manager": {
					Roles: []string{"contractor"},
				},
			},
		},
	}

	require.NoError(t, impl.IndexParentRoles(ctx, scopeParentRoles))

	t.Run("transitive closure", func(t *testing.T) {
		roles, err := impl.AddParentRoles(ctx, []string{"acme"}, []string{"manager"})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"manager", "employee", "user"}, roles)
	})

	t.Run("scope union", func(t *testing.T) {
		roles, err := impl.AddParentRoles(ctx, []string{"acme", "acme.hr"}, []string{"manager"})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"manager", "employee", "user", "contractor"}, roles)
	})

	t.Run("replace existing parent role index", func(t *testing.T) {
		require.NoError(t, impl.IndexParentRoles(ctx, map[string]*runtimev1.RuleTable_RoleParentRoles{}))

		roles, err := impl.AddParentRoles(ctx, []string{"acme", "acme.hr"}, []string{"manager"})
		require.NoError(t, err)
		require.Equal(t, []string{"manager"}, roles)
	})
}
