// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package scopeperms_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/policy/scopeperms"
)

const (
	unspecified = policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED
	override    = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
	consent     = policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
)

func TestTracker(t *testing.T) {
	t.Run("agreeing policies", func(t *testing.T) {
		tr := scopeperms.NewTracker()
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", unspecified)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/acme", "acme", override)
		tr.Add(policyv1.Kind_KIND_PRINCIPAL, "principal.p.vdefault/acme", "acme", override)

		require.Empty(t, tr.Conflicts())
		require.NoError(t, tr.Err())
		require.Equal(t, override, tr.Permissions("acme"))
		require.Equal(t, unspecified, tr.Permissions("unknown"))
	})

	t.Run("first policy is not forgotten", func(t *testing.T) {
		tr := scopeperms.NewTracker()
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", unspecified)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/acme", "acme", consent)

		conflicts := tr.Conflicts()
		require.Len(t, conflicts, 1)
		require.Equal(t, scopeperms.Conflict{
			Scope: "acme",
			PolicySettings: []scopeperms.PolicySetting{
				{PolicyKey: "resource.a.vdefault/acme", Permissions: override},
				{PolicyKey: "resource.b.vdefault/acme", Permissions: consent},
			},
		}, conflicts[0])
		require.Error(t, tr.Err())
		require.Equal(t, unspecified, tr.Permissions("acme"))
	})

	t.Run("role policies are ignored", func(t *testing.T) {
		tr := scopeperms.NewTracker()
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", consent)
		tr.Add(policyv1.Kind_KIND_ROLE_POLICY, "role.r/acme", "acme", unspecified)

		require.Empty(t, tr.Conflicts())
		require.Equal(t, consent, tr.Permissions("acme"))
	})

	t.Run("removal resolves a conflict", func(t *testing.T) {
		tr := scopeperms.NewTracker()
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", override)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/acme", "acme", consent)
		require.Len(t, tr.Conflicts(), 1)

		tr.Remove("resource.a.vdefault/acme")
		require.Empty(t, tr.Conflicts())
		require.Equal(t, consent, tr.Permissions("acme"))

		tr.Remove("resource.b.vdefault/acme")
		require.Equal(t, unspecified, tr.Permissions("acme"))
	})

	t.Run("re-adding replaces the setting", func(t *testing.T) {
		tr := scopeperms.NewTracker()
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", override)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/acme", "acme", consent)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", consent)

		require.Empty(t, tr.Conflicts())
		require.Equal(t, consent, tr.Permissions("acme"))
	})

	t.Run("check does not mutate", func(t *testing.T) {
		tr := scopeperms.NewTracker()
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", override)

		require.Nil(t, tr.Check(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/acme", "acme", unspecified, ""))
		require.Nil(t, tr.Check(policyv1.Kind_KIND_ROLE_POLICY, "role.r/acme", "acme", consent, ""))
		require.Nil(t, tr.Check(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/acme", "acme", consent, ""), "replacing own setting is not a conflict")
		require.Nil(t, tr.Check(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/acme", "acme", consent, "resource.a.vdefault/acme"), "the ignored policy is not considered")

		c := tr.Check(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/acme", "acme", consent, "")
		require.NotNil(t, c)
		require.Equal(t, "acme", c.Scope)
		require.Equal(t, []scopeperms.PolicySetting{
			{PolicyKey: "resource.a.vdefault/acme", Permissions: override},
			{PolicyKey: "resource.b.vdefault/acme", Permissions: consent},
		}, c.PolicySettings)

		require.Empty(t, tr.Conflicts())
		require.Equal(t, override, tr.Permissions("acme"))
	})

	t.Run("conflicts are sorted by scope", func(t *testing.T) {
		tr := scopeperms.NewTracker()
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/b", "b", override)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/b", "b", consent)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.a.vdefault/a", "a", override)
		tr.Add(policyv1.Kind_KIND_RESOURCE, "resource.b.vdefault/a", "a", consent)

		conflicts := tr.Conflicts()
		require.Len(t, conflicts, 2)
		require.Equal(t, "a", conflicts[0].Scope)
		require.Equal(t, "b", conflicts[1].Scope)
	})
}
