// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func ResourcePolicyRuleProtoPath(idx int) string {
	return fmt.Sprintf("resource_policy.rules[%d]", idx)
}

func ResourcePolicyRuleReferencedDerivedRoleProtoPath(ruleIdx, roleIdx int) string {
	return fmt.Sprintf("%s.derived_roles[%d]", ResourcePolicyRuleProtoPath(ruleIdx), roleIdx)
}

func ResourcePolicyImportDerivedRolesProtoPath(idx int) string {
	return fmt.Sprintf("resource_policy.import_derived_roles[%d]", idx)
}

func ResourcePolicyPrincipalSchemaProtoPath() string {
	return "resource_policy.schemas.principal_schema.ref"
}

func ResourcePolicyResourceSchemaProtoPath() string {
	return "resource_policy.schemas.resource_schema.ref"
}

func PrincipalPolicyRuleProtoPath(idx int) string {
	return fmt.Sprintf("principal_policy.rules[%d]", idx)
}

func PrincipalPolicyActionRuleProtoPath(parentIdx, idx int) string {
	return fmt.Sprintf("%s.actions[%d]", PrincipalPolicyRuleProtoPath(parentIdx), idx)
}

func RolePolicyRuleProtoPath(idx int) string {
	return fmt.Sprintf("role_policy.rules[%d]", idx)
}

func RolePolicyConditionProtoPath(idx int) string {
	return fmt.Sprintf("%s.condition", RolePolicyRuleProtoPath(idx))
}

func DerivedRoleConditionProtoPath(idx int) string {
	return fmt.Sprintf("%s.condition", DerivedRoleRuleProtoPath(idx))
}

func DerivedRoleRuleProtoPath(idx int) string {
	return fmt.Sprintf("derived_roles.definitions[%d]", idx)
}

func ExportConstantsConstantProtoPath() string {
	return "export_constants.definitions"
}

func ConstantsImportProtoPath(p *policyv1.Policy, idx int) string {
	return fmt.Sprintf("%s.constants.import[%d]", policyKind(p), idx)
}

func ConstantsLocalProtoPath(p *policyv1.Policy) string {
	return fmt.Sprintf("%s.constants.local", policyKind(p))
}

func ExportVariablesVariableProtoPath() string {
	return "export_variables.definitions"
}

func VariablesImportProtoPath(p *policyv1.Policy, idx int) string {
	return fmt.Sprintf("%s.variables.import[%d]", policyKind(p), idx)
}

func VariablesLocalProtoPath(p *policyv1.Policy) string {
	return fmt.Sprintf("%s.variables.local", policyKind(p))
}

func policyKind(p *policyv1.Policy) string {
	switch p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return "resource_policy"
	case *policyv1.Policy_PrincipalPolicy:
		return "principal_policy"
	case *policyv1.Policy_DerivedRoles:
		return "derived_roles"
	case *policyv1.Policy_ExportConstants:
		return "export_constants"
	case *policyv1.Policy_ExportVariables:
		return "export_variables"
	default:
		return ""
	}
}
