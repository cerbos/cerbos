// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func TestRoleParentRoles(t *testing.T) {
	rt := NewProtoRuletable()

	versioned := func(version, scope, role string) []string {
		return rt.VersionScopeParentRoles[version].GetScopes()[scope].GetRoleParentRoles()[role].GetRoles()
	}
	legacy := func(scope, role string) []string {
		return rt.ScopeParentRoles[scope].GetRoleParentRoles()[role].GetRoles() //nolint:staticcheck
	}

	setRoleParentRoles(rt, "v2", "acme", "agent", []string{"editor"})
	setRoleParentRoles(rt, "v1", "acme", "agent", []string{"viewer"})
	setRoleParentRoles(rt, "v1", "acme", "clerk", []string{"user"})

	t.Run("versions do not collide", func(t *testing.T) {
		require.Equal(t, []string{"viewer"}, versioned("v1", "acme", "agent"))
		require.Equal(t, []string{"editor"}, versioned("v2", "acme", "agent"))
		require.Empty(t, versioned("v2", "acme", "clerk"))
	})

	t.Run("legacy field holds the parent roles of the version that sorts first", func(t *testing.T) {
		require.Equal(t, []string{"viewer"}, legacy("acme", "agent"))
		require.Equal(t, []string{"user"}, legacy("acme", "clerk"))

		// whatever order the versions are added in
		other := NewProtoRuletable()
		setRoleParentRoles(other, "v1", "acme", "agent", []string{"viewer"})
		setRoleParentRoles(other, "v2", "acme", "agent", []string{"editor"})
		require.Equal(t, []string{"viewer"}, other.ScopeParentRoles["acme"].GetRoleParentRoles()["agent"].GetRoles()) //nolint:staticcheck
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
		require.Empty(t, rt.ScopeParentRoles) //nolint:staticcheck
	})
}

// TestMigrateParentRoles checks that a rule table built before VersionScopeParentRoles existed gets it
// populated from ScopeParentRoles and the role policy metadata.
func TestMigrateParentRoles(t *testing.T) {
	const legacyCompilerVersion = 2

	mkLegacy := func(t *testing.T) (*runtimev1.RuleTable, map[string]*runtimev1.RuleTable_ScopeParentRoles) {
		t.Helper()

		store, err := disk.NewStore(t.Context(), &disk.Conf{Directory: test.PathToDir(t, "store")})
		require.NoError(t, err)

		protoRT := NewProtoRuletable()
		require.NoError(t, LoadPolicies(t.Context(), protoRT, compile.NewManager(store)))
		require.NotEmpty(t, protoRT.VersionScopeParentRoles)

		want := protoRT.VersionScopeParentRoles
		protoRT.VersionScopeParentRoles = nil
		protoRT.CompilerVersion = legacyCompilerVersion

		return protoRT, want
	}

	parents := func(m map[string]*runtimev1.RuleTable_ScopeParentRoles, version, scope, role string) []string {
		return m[version].GetScopes()[scope].GetRoleParentRoles()[role].GetRoles()
	}

	type scopeRole struct {
		scope, role string
	}

	// versionsOf lists the versions that each role policy exists in. A role policy that exists in
	// several versions only has the parent roles of one of them in the legacy rule table.
	versionsOf := func(m map[string]*runtimev1.RuleTable_ScopeParentRoles) map[scopeRole][]string {
		out := make(map[scopeRole][]string)
		for version, scopes := range m {
			for scope, roles := range scopes.GetScopes() {
				for role := range roles.GetRoleParentRoles() {
					sr := scopeRole{scope: scope, role: role}
					out[sr] = append(out[sr], version)
				}
			}
		}
		for _, versions := range out {
			slices.Sort(versions)
		}
		return out
	}

	t.Run("restores versions from metadata", func(t *testing.T) {
		protoRT, want := mkLegacy(t)
		legacy := protoRT.ScopeParentRoles //nolint:staticcheck
		require.NoError(t, migrate(protoRT))

		have := protoRT.VersionScopeParentRoles
		require.Equal(t, versionsOf(want), versionsOf(have))

		for sr, versions := range versionsOf(want) {
			for _, version := range versions {
				wantParents := parents(want, version, sr.scope, sr.role)
				if len(versions) > 1 {
					// all versions get the parent roles that survived in the legacy rule table
					wantParents = legacy[sr.scope].GetRoleParentRoles()[sr.role].GetRoles()
				}
				require.Equal(t, wantParents, parents(have, version, sr.scope, sr.role), "version=%s scope=%s role=%s", version, sr.scope, sr.role)
			}
		}
	})

	t.Run("legacy rule table evaluates parent roles", func(t *testing.T) {
		protoRT, _ := mkLegacy(t)
		rt, err := NewRuleTable(protoRT)
		require.NoError(t, err)

		require.ElementsMatch(t, []string{"relic_specialist", "expedition_member"}, rt.idx.AddParentRoles("default", "", []string{"relic_specialist"}))
		require.Equal(t, []string{"relic_specialist"}, rt.idx.AddParentRoles("v1", "", []string{"relic_specialist"}))
	})

	t.Run("does not overwrite existing versioned parent roles", func(t *testing.T) {
		protoRT, want := mkLegacy(t)
		protoRT.VersionScopeParentRoles = want

		before := proto.CloneOf(protoRT)
		require.NoError(t, migrate(protoRT))

		require.Empty(t, cmp.Diff(before, protoRT, protocmp.Transform()))
	})
}
