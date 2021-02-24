package namer

import (
	"fmt"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
)

const (
	ModulePrefix            = "paams"
	DerivedRolesPrefix      = "derived_roles"
	PrincipalPoliciesPrefix = "principal"
	ResourcePoliciesPrefix  = "resource"
	DefaultVersion          = "default"
)

// ModuleName returns the name of the module that will be generated for the given policy.
func ModuleName(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return ResourcePolicyModuleName(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version)
	case *policyv1.Policy_PrincipalPolicy:
		return PrincipalPolicyModuleName(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version)
	case *policyv1.Policy_DerivedRoles:
		return DerivedRolesModuleName(pt.DerivedRoles.Name)
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

// ResourcePolicyModuleName returns the module name for the resource policy with given resource and version.
func ResourcePolicyModuleName(resource, version string) string {
	return fmt.Sprintf("%s.%s.%s.v%s", ModulePrefix, ResourcePoliciesPrefix, resource, version)
}

// PrincipalPolicyModuleName returns the module name for the principal policy with given principal and version.
func PrincipalPolicyModuleName(principal, version string) string {
	return fmt.Sprintf("%s.%s.%s.v%s", ModulePrefix, PrincipalPoliciesPrefix, principal, version)
}

// DerivedRolesModuleName returns the module name for the given derived roles set.
func DerivedRolesModuleName(roleSetName string) string {
	return fmt.Sprintf("%s.%s.%s", ModulePrefix, DerivedRolesPrefix, roleSetName)
}

// EffectQueryForPrincipal returns the effect query for the given principal and version.
func EffectQueryForPrincipal(principal, version string) string {
	return fmt.Sprintf("data.%s.effect", PrincipalPolicyModuleName(principal, version))
}

// EffectQueryForResource returns the effect query for the given resource and version.
func EffectQueryForResource(resource, version string) string {
	return fmt.Sprintf("data.%s.effect", ResourcePolicyModuleName(resource, version))
	//return "data.paams.resource.leave_request.v20210210.effect"
}
