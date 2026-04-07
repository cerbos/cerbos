// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package namer

import (
	"database/sql"
	"database/sql/driver"
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func (m *ModuleID) Scan(src any) error {
	switch v := src.(type) {
	case uint64:
		m.hash = v
		return nil
	case int64:
		m.hash = uint64(v)
		return nil
	default:
		// hack to work around unpredictable behaviour from the MySQL driver (it's a feature, not a bug).
		// https://github.com/go-sql-driver/mysql/issues/861
		val := sql.NullInt64{}
		if err := val.Scan(src); err == nil {
			m.hash = uint64(val.Int64)
			return nil
		}

		return fmt.Errorf("unexpected type for module ID: %T", src)
	}
}

func (m ModuleID) Value() (driver.Value, error) {
	return m.hash, nil
}

// GenModuleID generates a short ID for the module.
func GenModuleID(p *policyv1.Policy) ModuleID {
	return GenModuleIDFromFQN(FQN(p))
}

// FQN returns the fully-qualified name of the policy.
func FQN(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return ResourcePolicyFQN(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version, pt.ResourcePolicy.Scope)
	case *policyv1.Policy_PrincipalPolicy:
		return PrincipalPolicyFQN(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version, pt.PrincipalPolicy.Scope)
	case *policyv1.Policy_RolePolicy:
		return RolePolicyFQN(pt.RolePolicy.GetRole(), pt.RolePolicy.Version, pt.RolePolicy.Scope)
	case *policyv1.Policy_DerivedRoles:
		return DerivedRolesFQN(pt.DerivedRoles.Name)
	case *policyv1.Policy_ExportConstants:
		return ExportConstantsFQN(pt.ExportConstants.Name)
	case *policyv1.Policy_ExportVariables:
		return ExportVariablesFQN(pt.ExportVariables.Name)
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

// FQNTree returns the tree of FQNs that are ancestors of the given policy (including itself) sorted by most recent to oldest.
// For example, if the policy has scope a.b.c, the returned tree will contain the FQNs in the following order:
// - a.b.c
// - a.b
// - a
// - "" (empty scope).
func FQNTree(p *policyv1.Policy) []string {
	var fqn string
	var scope string

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		fqn = ResourcePolicyFQN(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version, "")
		scope = pt.ResourcePolicy.Scope
	case *policyv1.Policy_PrincipalPolicy:
		fqn = PrincipalPolicyFQN(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version, "")
		scope = pt.PrincipalPolicy.Scope
	case *policyv1.Policy_RolePolicy:
		// role policies don't functionally have ancestors
		fqn = RolePolicyFQN(pt.RolePolicy.GetRole(), pt.RolePolicy.Version, pt.RolePolicy.Scope)
		return []string{fqn}
	case *policyv1.Policy_DerivedRoles:
		fqn = DerivedRolesFQN(pt.DerivedRoles.Name)
	case *policyv1.Policy_ExportConstants:
		fqn = ExportConstantsFQN(pt.ExportConstants.Name)
	case *policyv1.Policy_ExportVariables:
		fqn = ExportVariablesFQN(pt.ExportVariables.Name)
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}

	return buildFQNTree(fqn, scope, func(s string) string { return s })
}

// PolicyKey returns a human-friendly identifier that can be used to refer to the policy in logs and other outputs.
func PolicyKey(p *policyv1.Policy) string {
	return PolicyKeyFromFQN(FQN(p))
}

// ResourceRuleName returns the name of the given resource rule.
func ResourceRuleName(rule *policyv1.ResourceRule, idx int) string {
	if rule.Name != "" {
		return rule.Name
	}

	return fmt.Sprintf("rule-%03d", idx)
}

// PrincipalResourceActionRuleName returns the name for an action rule defined for a particular resource.
func PrincipalResourceActionRuleName(rule *policyv1.PrincipalRule_Action, resource string, idx int) string {
	if rule.Name != "" {
		return rule.Name
	}

	return fmt.Sprintf("%s_rule-%03d", resource, idx)
}
