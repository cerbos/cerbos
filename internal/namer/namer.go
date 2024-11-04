// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package namer

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/util"
)

var (
	invalidIdentifierChars = regexp.MustCompile(`[^\w.]+`)
	// Naming pattern imposed on resource and principal names before Cerbos 0.30.0.
	oldNamePattern = regexp.MustCompile(`^[[:alpha:]][[:word:]\@\.\-/]*(\:[[:alpha:]][[:word:]\@\.\-/]*)*$`)
)

const (
	DerivedRolesPrefix      = fqnPrefix + "derived_roles"
	ExportConstantsPrefix   = fqnPrefix + "export_constants"
	ExportVariablesPrefix   = fqnPrefix + "export_variables"
	PrincipalPoliciesPrefix = fqnPrefix + "principal"
	ResourcePoliciesPrefix  = fqnPrefix + "resource"
	RolePoliciesPrefix      = fqnPrefix + "role"

	DefaultVersion = "default"
	fqnPrefix      = "cerbos."
)

// ModuleID is a unique identifier for modules.
type ModuleID struct {
	hash uint64
}

func (m ModuleID) Value() (driver.Value, error) {
	return m.hash, nil
}

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

func (m *ModuleID) String() string {
	return strconv.FormatUint(m.hash, 10)
}

func (m *ModuleID) HexStr() string {
	return fmt.Sprintf("%X", m.hash)
}

func (m ModuleID) RawValue() uint64 {
	return m.hash
}

// GenModuleID generates a short ID for the module.
func GenModuleID(p *policyv1.Policy) ModuleID {
	return GenModuleIDFromFQN(FQN(p))
}

// GenModuleIDFromFQN generates a short ID for the given module name.
func GenModuleIDFromFQN(name string) ModuleID {
	return ModuleID{hash: util.HashStr(name)}
}

// FQN returns the fully-qualified name of the policy.
func FQN(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return ResourcePolicyFQN(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version, pt.ResourcePolicy.Scope)
	case *policyv1.Policy_PrincipalPolicy:
		return PrincipalPolicyFQN(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version, pt.PrincipalPolicy.Scope)
	case *policyv1.Policy_RolePolicy:
		return RolePolicyFQN(pt.RolePolicy.GetRole(), pt.RolePolicy.Scope)
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
		fqn = RolePolicyFQN(pt.RolePolicy.GetRole(), pt.RolePolicy.Scope)
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

func buildFQNTree[T any](fqn, scope string, elementFn func(string) T) []T {
	if scope == "" {
		return []T{elementFn(fqn)}
	}

	fqnTree := []T{elementFn(withScope(fqn, scope))}

	for i := len(scope) - 1; i >= 0; i-- {
		if scope[i] == '.' {
			fqnTree = append(fqnTree, elementFn(withScope(fqn, scope[:i])))
		}
	}

	// add the no scope FQN as the root
	fqnTree = append(fqnTree, elementFn(fqn))

	return fqnTree
}

func ScopeFromFQN(fqn string) string {
	_, scope, _ := strings.Cut(fqn, "/")
	return scope
}

// PolicyKey returns a human-friendly identifier that can be used to refer to the policy in logs and other outputs.
func PolicyKey(p *policyv1.Policy) string {
	return PolicyKeyFromFQN(FQN(p))
}

// PolicyKeyFromFQN returns a policy key from the module name.
func PolicyKeyFromFQN(m string) string {
	return strings.TrimPrefix(m, fqnPrefix)
}

// FQNFromPolicyKey returns FQN from the policy key.
func FQNFromPolicyKey(s string) string {
	return fqnPrefix + s
}

// ResourcePolicyFQN returns the fully-qualified name for the resource policy with given resource, version and scope.
func ResourcePolicyFQN(resource, version, scope string) string {
	fqn := fmt.Sprintf("%s.%s.v%s", ResourcePoliciesPrefix, sanitize(resource), sanitize(version))
	return withScope(fqn, scope)
}

// ResourcePolicyModuleID returns the module ID for the resource policy with given resource, version and scope.
func ResourcePolicyModuleID(resource, version, scope string) ModuleID {
	return GenModuleIDFromFQN(ResourcePolicyFQN(resource, version, scope))
}

// ScopedResourcePolicyModuleIDs returns a list of module IDs for each scope segment if `genTree` is true.
// For example, if the scope is `a.b.c`, the list will contain the module IDs for scopes `a.b.c`, `a.b`, `a` and `""` in that order.
func ScopedResourcePolicyModuleIDs(resource, version, scope string, genTree bool) []ModuleID {
	if !genTree || scope == "" {
		return []ModuleID{ResourcePolicyModuleID(resource, version, scope)}
	}

	return buildFQNTree(ResourcePolicyFQN(resource, version, ""), scope, GenModuleIDFromFQN)
}

// PrincipalPolicyFQN returns the fully-qualified module name for the principal policy with given principal, version and scope.
func PrincipalPolicyFQN(principal, version, scope string) string {
	fqn := fmt.Sprintf("%s.%s.v%s", PrincipalPoliciesPrefix, sanitize(principal), sanitize(version))
	return withScope(fqn, scope)
}

// PrincipalPolicyModuleID returns the module ID for the principal policy with given principal and version.
func PrincipalPolicyModuleID(principal, version, scope string) ModuleID {
	return GenModuleIDFromFQN(PrincipalPolicyFQN(principal, version, scope))
}

// RolePolicyFQN returns the fully-qualified module name for the role policies with the given scope.
func RolePolicyFQN(role, scope string) string {
	fqn := fmt.Sprintf("%s.%s", RolePoliciesPrefix, sanitize(role))
	return withScope(fqn, scope)
}

// RolePolicyModuleID returns the module ID for the role policies with the given scope.
func RolePolicyModuleID(role, scope string) ModuleID {
	return GenModuleIDFromFQN(RolePolicyFQN(role, scope))
}

// ScopedPrincipalPolicyModuleIDs returns a list of module IDs for each scope segment if `strict` is false.
// For example, if the scope is `a.b.c`, the list will contain the module IDs for scopes `a.b.c`, `a.b`, `a` and `""` in that order.
func ScopedPrincipalPolicyModuleIDs(principal, version, scope string, genTree bool) []ModuleID {
	if !genTree || scope == "" {
		return []ModuleID{PrincipalPolicyModuleID(principal, version, scope)}
	}

	return buildFQNTree(PrincipalPolicyFQN(principal, version, ""), scope, GenModuleIDFromFQN)
}

// DerivedRolesFQN returns the fully-qualified module name for the given derived roles set.
func DerivedRolesFQN(roleSetName string) string {
	return fmt.Sprintf("%s.%s", DerivedRolesPrefix, sanitize(roleSetName))
}

// DerivedRolesModuleID returns the module ID for the given derived roles set.
func DerivedRolesModuleID(roleSetName string) ModuleID {
	return GenModuleIDFromFQN(DerivedRolesFQN(roleSetName))
}

// ExportConstantsFQN returns the fully-qualified module name for the given exported constant definitions.
func ExportConstantsFQN(constantsName string) string {
	return fmt.Sprintf("%s.%s", ExportConstantsPrefix, sanitize(constantsName))
}

// ExportConstantsModuleID returns the module ID for the given exported constant definitions.
func ExportConstantsModuleID(constantsName string) ModuleID {
	return GenModuleIDFromFQN(ExportConstantsFQN(constantsName))
}

// ExportVariablesFQN returns the fully-qualified module name for the given exported variable definitions.
func ExportVariablesFQN(variablesName string) string {
	return fmt.Sprintf("%s.%s", ExportVariablesPrefix, sanitize(variablesName))
}

// ExportVariablesModuleID returns the module ID for the given exported variable definitions.
func ExportVariablesModuleID(variablesName string) ModuleID {
	return GenModuleIDFromFQN(ExportVariablesFQN(variablesName))
}

// SimpleName extracts the simple name from a derived roles, exported constants, or exported variables FQN.
func SimpleName(fqn string) string {
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(fqn, ExportVariablesPrefix+"."), ExportConstantsPrefix+"."), DerivedRolesPrefix+".")
}

func withScope(fqn, scope string) string {
	if scope == "" {
		return fqn
	}

	return fqn + "/" + scope
}

// sanitize replaces special characters in the string with underscores.
// Before Cerbos 0.30 the names of resources or principals had to follow a certain pattern. We then replaced some of
// the non-word characters with underscores because earlier versions of Cerbos used to generate Rego code for policies.
// Because we used the sanitized name for computing the module ID of the policy, in order to maintain backward compatibility
// and not break database stores we still have to do the same if the name matches the pattern.
func sanitize(v string) string {
	if oldNamePattern.MatchString(v) {
		return invalidIdentifierChars.ReplaceAllLiteralString(v, "_")
	}
	return v
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

// RuleFQN returns the FQN for the resource rule or principal resource action rule with scope granularity.
func RuleFQN(rpsMeta any, scope, ruleName string) string {
	var policyFqn string

	switch m := rpsMeta.(type) {
	case *runtimev1.RunnableResourcePolicySet_Metadata:
		policyFqn = ResourcePolicyFQN(m.Resource, m.Version, scope)
	case *runtimev1.RunnablePrincipalPolicySet_Metadata:
		policyFqn = PrincipalPolicyFQN(m.Principal, m.Version, scope)
	default:
		panic(fmt.Errorf("unknown runnable policy set meta type %T", m))
	}

	return fmt.Sprintf("%s#%s", PolicyKeyFromFQN(policyFqn), ruleName)
}

type PolicyCoords struct {
	Kind    string
	Name    string
	Version string
	Scope   string
}

func (pc PolicyCoords) FQN() string {
	prefix := fqnPrefix + strings.ToLower(pc.Kind)
	switch prefix {
	case DerivedRolesPrefix:
		return DerivedRolesFQN(pc.Name)
	case ExportConstantsPrefix:
		return ExportConstantsFQN(pc.Name)
	case ExportVariablesPrefix:
		return ExportVariablesFQN(pc.Name)
	case PrincipalPoliciesPrefix:
		return PrincipalPolicyFQN(pc.Name, pc.Version, pc.Scope)
	case ResourcePoliciesPrefix:
		return ResourcePolicyFQN(pc.Name, pc.Version, pc.Scope)
	case RolePoliciesPrefix:
		return RolePolicyFQN(pc.Name, pc.Scope)
	default:
		panic(fmt.Errorf("unknown kind %q", pc.Kind))
	}
}

func (pc PolicyCoords) PolicyKey() string {
	return PolicyKeyFromFQN(pc.FQN())
}
