// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package namer

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cespare/xxhash"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

var invalidIdentiferChars = regexp.MustCompile(`[^\w\.]+`)

const (
	DerivedRolesPrefix      = "cerbos.derived_roles"
	PrincipalPoliciesPrefix = "cerbos.principal"
	ResourcePoliciesPrefix  = "cerbos.resource"

	DefaultVersion = "default"
)

// ModuleID is a unique identifier for modules.
type ModuleID struct {
	hash uint64
}

func (m ModuleID) Value() (driver.Value, error) {
	return m.hash, nil
}

func (m *ModuleID) Scan(src interface{}) error {
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

func (m *ModuleID) String() string {
	return strconv.FormatUint(m.hash, 10) //nolint:gomnd
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

// PolicyKey returns a human-friendly identifier that can be used to refer to the policy in logs and other outputs.
func PolicyKey(p *policyv1.Policy) string {
	return PolicyKeyFromModuleName(ModuleName(p))
}

// PolicyKeyFromModuleName returns a policy key from the module name.
func PolicyKeyFromModuleName(m string) string {
	return strings.TrimPrefix(m, "cerbos.")
}

// ResourcePolicyModuleName returns the module name for the resource policy with given resource and version.
func ResourcePolicyModuleName(resource, version string) string {
	return fmt.Sprintf("%s.%s.v%s", ResourcePoliciesPrefix, Sanitize(resource), Sanitize(version))
}

// ResourcePolicyModuleID returns the module ID for the resource policy with given resource and version.
func ResourcePolicyModuleID(resource, version string) ModuleID {
	return GenModuleIDFromName(ResourcePolicyModuleName(resource, version))
}

// PrincipalPolicyModuleName returns the module name for the principal policy with given principal and version.
func PrincipalPolicyModuleName(principal, version string) string {
	return fmt.Sprintf("%s.%s.v%s", PrincipalPoliciesPrefix, Sanitize(principal), Sanitize(version))
}

// PrincipalPolicyModuleID returns the module ID for the principal policy with given principal and version.
func PrincipalPolicyModuleID(principal, version string) ModuleID {
	return GenModuleIDFromName(PrincipalPolicyModuleName(principal, version))
}

// DerivedRolesModuleName returns the module name for the given derived roles set.
func DerivedRolesModuleName(roleSetName string) string {
	return fmt.Sprintf("%s.%s", DerivedRolesPrefix, Sanitize(roleSetName))
}

// DerivedRolesModuleID returns the module ID for the given derived roles set.
func DerivedRolesModuleID(roleSetName string) ModuleID {
	return GenModuleIDFromName(DerivedRolesModuleName(roleSetName))
}

// DerivedRolesSimpleName extracts the simple name from a derived roles module name.
func DerivedRolesSimpleName(modName string) string {
	return strings.TrimPrefix(modName, DerivedRolesPrefix+".")
}

// QueryForPrincipal returns the effect query for the given principal and version.
func QueryForPrincipal(principal, version string) string {
	return fmt.Sprintf("data.%s", PrincipalPolicyModuleName(principal, version))
}

// QueryForResource returns the effect query for the given resource and version.
func QueryForResource(resource, version string) string {
	return fmt.Sprintf("data.%s", ResourcePolicyModuleName(resource, version))
}

func Sanitize(v string) string {
	return invalidIdentiferChars.ReplaceAllLiteralString(v, "_")
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
