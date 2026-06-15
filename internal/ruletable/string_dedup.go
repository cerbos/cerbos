// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/ruletable/index"
)

func (rt *RuleTable) dedupStrings() {
	s := index.NewStringDeduper()

	for _, m := range rt.Meta {
		dedupMeta(s, m)
	}

	rt.ScopeParentRoles = dedupScopeParentRoles(s, rt.ScopeParentRoles)

	shared := make(map[uint64]*runtimev1.RunnableDerivedRole)
	for modID, drs := range rt.policyDerivedRoles {
		rt.policyDerivedRoles[modID] = dedupDerivedRoleMap(s, shared, drs)
	}

	rt.JsonSchemas = dedupJSONSchemas(s, rt.JsonSchemas)
	rt.principalScopeMap = dedupStringSet(s, rt.principalScopeMap)
	rt.resourceScopeMap = dedupStringSet(s, rt.resourceScopeMap)
	rt.scopeScopePermissions = dedupScopePermissions(s, rt.scopeScopePermissions)
	rt.idx.DedupStrings(s)
}

func dedupMeta(s *index.StringDeduper, m *runtimev1.RuleTableMetadata) {
	if m == nil {
		return
	}
	s.Intern(&m.Fqn)
	s.Intern(&m.Version)
	switch n := m.Name.(type) {
	case *runtimev1.RuleTableMetadata_Resource:
		s.Intern(&n.Resource)
	case *runtimev1.RuleTableMetadata_Role:
		s.Intern(&n.Role)
	case *runtimev1.RuleTableMetadata_Principal:
		s.Intern(&n.Principal)
	}
	if len(m.SourceAttributes) > 0 {
		out := make(map[string]*policyv1.SourceAttributes, len(m.SourceAttributes))
		for k, v := range m.SourceAttributes {
			s.Intern(&k)
			dedupSourceAttributes(s, v)
			out[k] = v
		}
		m.SourceAttributes = out
	}
	if len(m.Annotations) > 0 {
		out := make(map[string]string, len(m.Annotations))
		for k, v := range m.Annotations {
			s.Intern(&k)
			s.Intern(&v)
			out[k] = v
		}
		m.Annotations = out
	}
}

// dedupSourceAttributes interns keys and relocates each attribute value into a
// fresh, interned deep copy.
func dedupSourceAttributes(s *index.StringDeduper, sa *policyv1.SourceAttributes) {
	if sa == nil || len(sa.Attributes) == 0 {
		return
	}
	out := make(map[string]*structpb.Value, len(sa.Attributes))
	for k, v := range sa.Attributes {
		s.Intern(&k)
		out[k] = relocateValue(s, v)
	}
	sa.Attributes = out
}

// relocateValue returns a freshly-allocated deep copy of v with string leaves
// interned.
func relocateValue(s *index.StringDeduper, v *structpb.Value) *structpb.Value {
	if v == nil {
		return nil
	}
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		// Clone (not intern): attribute values are mostly unique (file paths).
		return structpb.NewStringValue(strings.Clone(k.StringValue))
	case *structpb.Value_NumberValue:
		return structpb.NewNumberValue(k.NumberValue)
	case *structpb.Value_BoolValue:
		return structpb.NewBoolValue(k.BoolValue)
	case *structpb.Value_NullValue:
		return structpb.NewNullValue()
	case *structpb.Value_StructValue:
		fields := k.StructValue.GetFields()
		out := make(map[string]*structpb.Value, len(fields))
		for fk, fv := range fields {
			s.Intern(&fk)
			out[fk] = relocateValue(s, fv)
		}
		return structpb.NewStructValue(&structpb.Struct{Fields: out})
	case *structpb.Value_ListValue:
		vals := k.ListValue.GetValues()
		out := make([]*structpb.Value, len(vals))
		for i, e := range vals {
			out[i] = relocateValue(s, e)
		}
		return structpb.NewListValue(&structpb.ListValue{Values: out})
	default:
		return v
	}
}

func dedupScopeParentRoles(s *index.StringDeduper, m map[string]*runtimev1.RuleTable_RoleParentRoles) map[string]*runtimev1.RuleTable_RoleParentRoles {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]*runtimev1.RuleTable_RoleParentRoles, len(m))
	for scope, rpr := range m {
		s.Intern(&scope)
		if rpr != nil && len(rpr.RoleParentRoles) > 0 {
			inner := make(map[string]*runtimev1.RuleTable_RoleParentRoles_ParentRoles, len(rpr.RoleParentRoles))
			for role, parents := range rpr.RoleParentRoles {
				s.Intern(&role)
				if parents != nil {
					for i := range parents.Roles {
						s.Intern(&parents.Roles[i])
					}
				}
				inner[role] = parents
			}
			rpr.RoleParentRoles = inner
		}
		out[scope] = rpr
	}
	return out
}

func dedupDerivedRoleMap(s *index.StringDeduper, shared map[uint64]*runtimev1.RunnableDerivedRole, m map[string]*WrappedRunnableDerivedRole) map[string]*WrappedRunnableDerivedRole {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]*WrappedRunnableDerivedRole, len(m))
	for k, v := range m {
		s.Intern(&k)
		if v != nil {
			if v.RunnableDerivedRole != nil {
				if c, ok := shared[v.VarCacheKey]; ok && proto.Equal(c, v.RunnableDerivedRole) {
					v.RunnableDerivedRole = c
				} else {
					dedupRunnableDerivedRole(s, v.RunnableDerivedRole)
					shared[v.VarCacheKey] = v.RunnableDerivedRole
				}
			}
			v.Constants = dedupAnyMap(s, v.Constants)
		}
		out[k] = v
	}
	return out
}

var empty = &emptypb.Empty{}

func dedupRunnableDerivedRole(s *index.StringDeduper, rdr *runtimev1.RunnableDerivedRole) {
	s.Intern(&rdr.Name)
	s.Intern(&rdr.OriginFqn)
	if len(rdr.ParentRoles) > 0 {
		out := make(map[string]*emptypb.Empty, len(rdr.ParentRoles))
		for k := range rdr.ParentRoles {
			s.Intern(&k)
			out[k] = empty
		}
		rdr.ParentRoles = out
	}
	if len(rdr.Constants) > 0 {
		out := make(map[string]*structpb.Value, len(rdr.Constants))
		for k, v := range rdr.Constants {
			s.Intern(&k)
			if vs := v.GetStringValue(); vs != "" {
				s.Intern(&vs)
				v = structpb.NewStringValue(vs)
			}
			out[k] = v
		}
		rdr.Constants = out
	}
	for i, v := range rdr.OrderedVariables {
		if v == nil {
			continue
		}
		s.Intern(&v.Name)
		if v.Expr != nil {
			s.Intern(&v.Expr.Original)
		}
		rdr.OrderedVariables[i] = proto.Clone(v).(*runtimev1.Variable) //nolint:forcetypeassert
	}
	s.DedupCondition(rdr.Condition)
	if rdr.Condition != nil {
		rdr.Condition = proto.Clone(rdr.Condition).(*runtimev1.Condition) //nolint:forcetypeassert
	}
}

func dedupAnyMap(s *index.StringDeduper, m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		s.Intern(&k)
		out[k] = v
	}
	return out
}

func dedupJSONSchemas(s *index.StringDeduper, m map[string]*runtimev1.RuleTable_JSONSchema) map[string]*runtimev1.RuleTable_JSONSchema {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]*runtimev1.RuleTable_JSONSchema, len(m))
	for k, v := range m {
		s.Intern(&k)
		out[k] = v
	}
	return out
}

func dedupStringSet(s *index.StringDeduper, m map[string]struct{}) map[string]struct{} {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]struct{}, len(m))
	for k := range m {
		s.Intern(&k)
		out[k] = struct{}{}
	}
	return out
}

func dedupScopePermissions(s *index.StringDeduper, m map[string]policyv1.ScopePermissions) map[string]policyv1.ScopePermissions {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]policyv1.ScopePermissions, len(m))
	for k, v := range m {
		s.Intern(&k)
		out[k] = v
	}
	return out
}
