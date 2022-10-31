// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

const (
	actionApprove = "approve"
	actionCreate  = "create"
	id            = "XX125"
	kind          = "leave_request"
	name          = "my_derived_roles"
	ref           = "cerbos:///principal.json"
	roleName      = "employee_that_owns_the_record"
	ruleName      = "rule-001"
	principal     = "bugs_bunny"
	resource      = "leave_request"
	scope         = "acme"
	version       = "v1"

	attrKey    = "department"
	attrValue  = "marketing"
	boolAttr   = true
	doubleAttr = 1.5
	stringAttr = "stringAttr"

	boolAttrKey   = "boolAttr"
	doubleAttrKey = "doubleAttr"
	listAttrKey   = "listAttr"
	mapAttrKey    = "mapAttr"
	stringAttrKey = "stringAttr"
)

var (
	attributes = map[string]any{
		boolAttrKey:   boolAttr,
		doubleAttrKey: doubleAttr,
		stringAttrKey: stringAttr,
		listAttrKey:   listAttr,
		mapAttrKey:    mapAttr,
	}
	listAttr = []any{"a", "b", "c"}
	mapAttr  = map[string]any{"a": "a", "b": "b", "c": "c"}
	roles    = []string{"user", "principal", "president"}
)

func TestBuilders(t *testing.T) {
	t.Run("DerivedRoles", func(t *testing.T) {
		dr := newDerivedRoles(t)
		require.NoError(t, dr.Validate())
		cmpDerivedRoles(t, dr)
	})
	t.Run("Principal", func(t *testing.T) {
		p := newPrincipal(t)
		require.NoError(t, p.Validate())
		cmpPrincipal(t, p)
	})
	t.Run("Resource", func(t *testing.T) {
		r := newResource(t)
		require.NoError(t, r.Validate())
		cmpResource(t, r)
	})
	t.Run("Schema", func(t *testing.T) {
		s := newSchema(t)
		require.NoError(t, s.Validate())
		cmpSchema(t, s)
	})

	t.Run("PrincipalPolicy", func(t *testing.T) {
		pp := newPrincipalPolicy(t)
		require.NoError(t, pp.Validate())
		cmpPrincipalPolicy(t, pp)
	})
	t.Run("ResourcePolicy", func(t *testing.T) {
		rp := newResourcePolicy(t)
		require.NoError(t, rp.Validate())
		cmpResourcePolicy(t, rp)
	})

	t.Run("PrincipalRule", func(t *testing.T) {
		pr := newPrincipalRule(t)
		require.NoError(t, pr.Validate())
		cmpPrincipalRule(t, pr)
	})
	t.Run("ResourceRule", func(t *testing.T) {
		rr := newResourceRule(t)
		require.NoError(t, rr.Validate())
		cmpResourceRule(t, rr)
	})

	t.Run("PolicySet", func(t *testing.T) {
		ps := newPolicySet(t)
		require.NoError(t, ps.Validate())
		cmpPolicySet(t, ps)
	})
	t.Run("ResourceSet", func(t *testing.T) {
		rs := newResourceSet(t)
		require.NoError(t, rs.Validate())
		cmpResourceSet(t, rs)
	})
}

func cmpDerivedRoles(t *testing.T, dr *DerivedRoles) {
	t.Helper()

	require.Equal(t, name, dr.dr.Name)
	require.Equal(t, roleName, dr.dr.Definitions[0].Name)
	for i, role := range roles {
		require.Equal(t, role, dr.dr.Definitions[0].ParentRoles[i])
	}
}

func cmpPrincipal(t *testing.T, p *Principal) {
	t.Helper()

	require.Equal(t, id, p.p.Id)

	require.Equal(t, boolAttr, p.p.Attr[boolAttrKey].GetBoolValue())
	require.Equal(t, stringAttr, p.p.Attr[stringAttrKey].GetStringValue())
	require.Equal(t, doubleAttr, p.p.Attr[doubleAttrKey].GetNumberValue())
	for i, val := range listAttr {
		require.Equal(t, val, p.p.Attr[listAttrKey].GetListValue().Values[i].GetStringValue())
	}
	for key, val := range mapAttr {
		require.Equal(t, val, p.p.Attr[mapAttrKey].GetStructValue().AsMap()[key].(string))
	}

	require.Equal(t, attrValue, p.p.Attr[attrKey].GetStringValue())
	require.Equal(t, version, p.p.PolicyVersion)
	for i, role := range roles {
		require.Equal(t, role, p.p.Roles[i])
	}
	require.Equal(t, scope, p.p.Scope)
}

func cmpResource(t *testing.T, r *Resource) {
	t.Helper()

	require.Equal(t, id, r.r.Id)
	require.Equal(t, kind, r.r.Kind)

	require.Equal(t, boolAttr, r.r.Attr[boolAttrKey].GetBoolValue())
	require.Equal(t, stringAttr, r.r.Attr[stringAttrKey].GetStringValue())
	require.Equal(t, doubleAttr, r.r.Attr[doubleAttrKey].GetNumberValue())
	for i, val := range listAttr {
		require.Equal(t, val, r.r.Attr[listAttrKey].GetListValue().Values[i].GetStringValue())
	}
	for key, val := range mapAttr {
		require.Equal(t, val, r.r.Attr[mapAttrKey].GetStructValue().AsMap()[key].(string))
	}

	require.Equal(t, attrValue, r.r.Attr[attrKey].GetStringValue())
	require.Equal(t, version, r.r.PolicyVersion)
	require.Equal(t, scope, r.r.Scope)
}

func cmpPrincipalPolicy(t *testing.T, pp *PrincipalPolicy) {
	t.Helper()

	require.Equal(t, principal, pp.pp.Principal)
	require.Equal(t, scope, pp.pp.Scope)
	require.Equal(t, version, pp.pp.Version)
}

func cmpResourcePolicy(t *testing.T, rp *ResourcePolicy) {
	t.Helper()

	require.Equal(t, resource, rp.p.Resource)
	require.Equal(t, scope, rp.p.Scope)
	require.Equal(t, version, rp.p.Version)
}

func cmpPrincipalRule(t *testing.T, pr *PrincipalRule) {
	t.Helper()

	require.Equal(t, resource, pr.rule.Resource)
	require.Equal(t, actionApprove, pr.rule.Actions[0].Action)
	require.Equal(t, actionCreate, pr.rule.Actions[1].Action)
	require.Equal(t, effectv1.Effect_EFFECT_ALLOW, pr.rule.Actions[0].Effect)
	require.Equal(t, effectv1.Effect_EFFECT_DENY, pr.rule.Actions[1].Effect)
}

func cmpResourceRule(t *testing.T, rr *ResourceRule) {
	t.Helper()

	require.Equal(t, actionApprove, rr.rule.Actions[0])
	for i, role := range roles {
		require.EqualValues(t, role, rr.rule.DerivedRoles[i])
	}
	for i, role := range roles {
		require.EqualValues(t, role, rr.rule.Roles[i])
	}
}

func cmpResourceSet(t *testing.T, rs *ResourceSet) {
	t.Helper()

	require.Equal(t, kind, rs.rs.Kind)
	require.Equal(t, version, rs.rs.PolicyVersion)

	require.Equal(t, boolAttr, rs.rs.Instances[id].Attr[boolAttrKey].GetBoolValue())
	require.Equal(t, stringAttr, rs.rs.Instances[id].Attr[stringAttrKey].GetStringValue())
	require.Equal(t, doubleAttr, rs.rs.Instances[id].Attr[doubleAttrKey].GetNumberValue())
	for i, val := range listAttr {
		require.Equal(t, val, rs.rs.Instances[id].Attr[listAttrKey].GetListValue().Values[i].GetStringValue())
	}
	for key, val := range mapAttr {
		require.Equal(t, val, rs.rs.Instances[id].Attr[mapAttrKey].GetStructValue().AsMap()[key].(string))
	}
}

func cmpPolicySet(t *testing.T, ps *PolicySet) {
	t.Helper()

	require.Len(t, ps.policies, 3)
	require.IsType(t, &policyv1.Policy_DerivedRoles{}, ps.policies[0].PolicyType)
	require.IsType(t, &policyv1.Policy_PrincipalPolicy{}, ps.policies[1].PolicyType)
	require.IsType(t, &policyv1.Policy_ResourcePolicy{}, ps.policies[2].PolicyType)
}

func cmpSchema(t *testing.T, s *Schema) {
	t.Helper()

	require.Equal(t, ref, s.s.Ref)
	require.Equal(t, actionApprove, s.s.IgnoreWhen.Actions[0])
}

func newDerivedRoles(t *testing.T) *DerivedRoles {
	t.Helper()

	return NewDerivedRoles(name).
		AddRole(roleName, roles)
}

func newPrincipal(t *testing.T) *Principal {
	t.Helper()

	return NewPrincipal(id, roles[0]).
		WithAttributes(attributes).
		WithAttr(attrKey, attrValue).
		WithPolicyVersion(version).
		WithRoles(roles[1], roles[2]).
		WithScope(scope)
}

func newResource(t *testing.T) *Resource {
	t.Helper()

	return NewResource(kind, id).
		WithAttributes(attributes).
		WithAttr(attrKey, attrValue).
		WithPolicyVersion(version).
		WithScope(scope)
}

func newPrincipalPolicy(t *testing.T) *PrincipalPolicy {
	t.Helper()

	return NewPrincipalPolicy(principal, version).
		WithScope(scope).
		AddPrincipalRules(
			newPrincipalRule(t),
		)
}

func newResourcePolicy(t *testing.T) *ResourcePolicy {
	t.Helper()

	return NewResourcePolicy(resource, version).
		WithScope(scope)
}

func newPrincipalRule(t *testing.T) *PrincipalRule {
	t.Helper()

	return NewPrincipalRule(resource).
		AllowAction(actionApprove).
		DenyAction(actionCreate)
}

func newResourceRule(t *testing.T) *ResourceRule {
	t.Helper()

	return NewAllowResourceRule(actionApprove).
		WithDerivedRoles(roles...).
		WithName(ruleName).
		WithRoles(roles...)
}

func newPolicySet(t *testing.T) *PolicySet {
	t.Helper()

	return NewPolicySet().
		AddDerivedRoles(newDerivedRoles(t)).
		AddPrincipalPolicies(newPrincipalPolicy(t)).
		AddResourcePolicies(newResourcePolicy(t))
}

func newResourceSet(t *testing.T) *ResourceSet {
	t.Helper()

	return NewResourceSet(kind).
		WithPolicyVersion(version).
		AddResourceInstance(id, attributes)
}

func newSchema(t *testing.T) *Schema {
	t.Helper()

	return NewSchema(ref).
		AddIgnoredActions(actionApprove)
}
