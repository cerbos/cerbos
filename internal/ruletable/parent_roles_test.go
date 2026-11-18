// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoleParentRoles(t *testing.T) {
	rt := NewProtoRuletable()

	versioned := func(version, scope, role string) []string {
		return rt.VersionScopeParentRoles[version].GetScopes()[scope].GetRoleParentRoles()[role].GetRoles()
	}
	legacy := func(scope, role string) []string {
		return rt.ScopeParentRoles[scope].GetRoleParentRoles()[role].GetRoles()
	}

	setRoleParentRoles(rt, "v2", "acme", "agent", []string{"editor"})
	setRoleParentRoles(rt, "v1", "acme", "agent", []string{"viewer"})
	setRoleParentRoles(rt, "v1", "acme", "clerk", []string{"user"})

	t.Run("versions do not collide", func(t *testing.T) {
		require.Equal(t, []string{"viewer"}, versioned("v1", "acme", "agent"))
		require.Equal(t, []string{"editor"}, versioned("v2", "acme", "agent"))
		require.Empty(t, versioned("v2", "acme", "clerk"))
	})

	t.Run("legacy field holds the parent roles of the last version added", func(t *testing.T) {
		require.Equal(t, []string{"viewer"}, legacy("acme", "agent"))
		require.Equal(t, []string{"user"}, legacy("acme", "clerk"))
	})

	t.Run("deleting a version keeps the other versions", func(t *testing.T) {
		deleteRoleParentRoles(rt, "v1", "acme", "agent")
		require.Empty(t, versioned("v1", "acme", "agent"))
		require.Equal(t, []string{"editor"}, versioned("v2", "acme", "agent"))
		require.Equal(t, []string{"user"}, versioned("v1", "acme", "clerk"))
	})

	t.Run("deleting a version repoints the legacy entry to a surviving version", func(t *testing.T) {
		require.Equal(t, []string{"editor"}, legacy("acme", "agent"))
		require.Equal(t, []string{"user"}, legacy("acme", "clerk"))
	})

	t.Run("deleting the last version clears everything", func(t *testing.T) {
		deleteRoleParentRoles(rt, "v2", "acme", "agent")
		deleteRoleParentRoles(rt, "v1", "acme", "clerk")
		require.Empty(t, rt.VersionScopeParentRoles)
		require.Empty(t, rt.ScopeParentRoles)
	})
}
