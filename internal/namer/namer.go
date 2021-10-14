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
	return GenModuleIDFromFQN(FQN(p))
}

// GenModuleIDFromFQN generates a short ID for the given module name.
func GenModuleIDFromFQN(name string) ModuleID {
	return ModuleID{hash: xxhash.Sum64String(name)}
}

// FQN returns the fully-qualified name of the policy.
func FQN(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return ResourcePolicyFQN(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version)
	case *policyv1.Policy_PrincipalPolicy:
		return PrincipalPolicyFQN(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version)
	case *policyv1.Policy_DerivedRoles:
		return DerivedRolesFQN(pt.DerivedRoles.Name)
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

// PolicyKey returns a human-friendly identifier that can be used to refer to the policy in logs and other outputs.
func PolicyKey(p *policyv1.Policy) string {
	return PolicyKeyFromFQN(FQN(p))
}

// PolicyKeyFromFQN returns a policy key from the module name.
func PolicyKeyFromFQN(m string) string {
	return strings.TrimPrefix(m, "cerbos.")
}

// ResourcePolicyFQN returns the fully-qualified name for the resource policy with given resource and version.
func ResourcePolicyFQN(resource, version string) string {
	return fmt.Sprintf("%s.%s.v%s", ResourcePoliciesPrefix, Sanitize(resource), Sanitize(version))
}

// ResourcePolicyModuleID returns the module ID for the resource policy with given resource and version.
func ResourcePolicyModuleID(resource, version string) ModuleID {
	return GenModuleIDFromFQN(ResourcePolicyFQN(resource, version))
}

// PrincipalPolicyFQN returns the fully-qualified module name for the principal policy with given principal and version.
func PrincipalPolicyFQN(principal, version string) string {
	return fmt.Sprintf("%s.%s.v%s", PrincipalPoliciesPrefix, Sanitize(principal), Sanitize(version))
}

// PrincipalPolicyModuleID returns the module ID for the principal policy with given principal and version.
func PrincipalPolicyModuleID(principal, version string) ModuleID {
	return GenModuleIDFromFQN(PrincipalPolicyFQN(principal, version))
}

// DerivedRolesFQN returns the fully-qualified module name for the given derived roles set.
func DerivedRolesFQN(roleSetName string) string {
	return fmt.Sprintf("%s.%s", DerivedRolesPrefix, Sanitize(roleSetName))
}

// DerivedRolesModuleID returns the module ID for the given derived roles set.
func DerivedRolesModuleID(roleSetName string) ModuleID {
	return GenModuleIDFromFQN(DerivedRolesFQN(roleSetName))
}

// DerivedRolesSimpleName extracts the simple name from a derived roles FQN.
func DerivedRolesSimpleName(fqn string) string {
	return strings.TrimPrefix(fqn, DerivedRolesPrefix+".")
}

// Sanitize replaces special characters in the string with underscores.
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
