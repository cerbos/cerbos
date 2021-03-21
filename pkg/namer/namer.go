package namer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cespare/xxhash"

	policyv1 "github.com/cerbos/cerbos/pkg/generated/policy/v1"
)

var invalidIdentiferChars = regexp.MustCompile(`[^\w\.]+`)

const (
	ModulePrefix            = "cerbos"
	DerivedRolesPrefix      = "derived_roles"
	PrincipalPoliciesPrefix = "principal"
	ResourcePoliciesPrefix  = "resource"
	DefaultVersion          = "default"
)

// ModuleID is a short ID to identify modules.
type ModuleID struct {
	hash uint64
}

// GenModuleID generates a short ID for the module.
func GenModuleID(p *policyv1.Policy) ModuleID {
	return GenModuleIDFromName(ModuleName(p))
}

// GenModuleIDFromName generates a short ID for the given module name.
func GenModuleIDFromName(name string) ModuleID {
	return ModuleID{hash: xxhash.Sum64String(name)}
}

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
	return fmt.Sprintf("%s.%s.%s.v%s", ModulePrefix, ResourcePoliciesPrefix, Sanitize(resource), Sanitize(version))
}

// ResourcePolicyModuleID returns the module ID for the resource policy with given resource and version.
func ResourcePolicyModuleID(resource, version string) ModuleID {
	return GenModuleIDFromName(ResourcePolicyModuleName(resource, version))
}

// PrincipalPolicyModuleName returns the module name for the principal policy with given principal and version.
func PrincipalPolicyModuleName(principal, version string) string {
	return fmt.Sprintf("%s.%s.%s.v%s", ModulePrefix, PrincipalPoliciesPrefix, Sanitize(principal), Sanitize(version))
}

// PrincipalPolicyModuleID returns the module ID for the principal policy with given principal and version.
func PrincipalPolicyModuleID(principal, version string) ModuleID {
	return GenModuleIDFromName(PrincipalPolicyModuleName(principal, version))
}

// DerivedRolesModuleName returns the module name for the given derived roles set.
func DerivedRolesModuleName(roleSetName string) string {
	return fmt.Sprintf("%s.%s.%s", ModulePrefix, DerivedRolesPrefix, Sanitize(roleSetName))
}

// DerivedRolesModuleID returns the module ID for the given derived roles set.
func DerivedRolesModuleID(roleSetName string) ModuleID {
	return GenModuleIDFromName(DerivedRolesModuleName(roleSetName))
}

// DerivedRolesSimpleName extracts the simple name from a derived roles module name.
func DerivedRolesSimpleName(modName string) string {
	return strings.TrimPrefix(modName, fmt.Sprintf("%s.%s.", ModulePrefix, DerivedRolesPrefix))
}

// EffectQueryForPrincipal returns the effect query for the given principal and version.
func EffectQueryForPrincipal(principal, version string) string {
	return fmt.Sprintf("data.%s.effect", PrincipalPolicyModuleName(principal, version))
}

// EffectQueryForResource returns the effect query for the given resource and version.
func EffectQueryForResource(resource, version string) string {
	return fmt.Sprintf("data.%s.effect", ResourcePolicyModuleName(resource, version))
}

func Sanitize(v string) string {
	return invalidIdentiferChars.ReplaceAllLiteralString(v, "_")
}
