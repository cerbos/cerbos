package internal

import (
	"fmt"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
)

const (
	ModulePrefix            = "paams"
	DerivedRolesPrefix      = "derived_roles"
	PrincipalPoliciesPrefix = "principal"
	ResourcePoliciesPrefix  = "resource"
)

func DerivedRolesModuleName(dr *policyv1.DerivedRoles) string {
	return fmt.Sprintf("%s.%s.%s", ModulePrefix, DerivedRolesPrefix, dr.Name)
}

func PolicyModuleName(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return fmt.Sprintf("%s.%s.%s.v%s", ModulePrefix, ResourcePoliciesPrefix, pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version)
	case *policyv1.Policy_PrincipalPolicy:
		return fmt.Sprintf("%s.%s.%s.v%s", ModulePrefix, PrincipalPoliciesPrefix, pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version)
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

func DerivedRolesImportName(imp string) string {
	return fmt.Sprintf("data.%s.%s.%s.%s", ModulePrefix, DerivedRolesPrefix, imp, derivedRolesMap)
}
