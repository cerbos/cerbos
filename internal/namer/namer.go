// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package namer

import (
	"fmt"
	"iter"
	"regexp"
	"strconv"
	"strings"

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
	DefaultScope   = ""
	fqnPrefix      = "cerbos."
)

// ModuleID is a unique identifier for modules.
type ModuleID struct {
	hash uint64
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

// GenModuleIDFromFQN generates a short ID for the given module name.
func GenModuleIDFromFQN(name string) ModuleID {
	return ModuleID{hash: util.HashStr(name)}
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

func ScopeParents(scope string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for i := len(scope) - 1; i >= 0; i-- {
			if scope[i] == '.' || i == 0 {
				if !yield(scope[:i]) {
					return
				}
			}
		}
	}
}

func ScopeFromFQN(fqn string) string {
	_, scope, _ := strings.Cut(fqn, "/")
	return scope
}

// PolicyKeyFromFQN returns a policy key from the module name.
func PolicyKeyFromFQN(m string) string {
	return strings.TrimPrefix(m, fqnPrefix)
}

// FQNFromPolicyKey returns FQN from the policy key.
func FQNFromPolicyKey(s string) string {
	return fqnPrefix + s
}

func SanitizedResource(resource string) string {
	return sanitize(resource)
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
// If version is empty, it defaults to DefaultVersion.
func RolePolicyFQN(role, version, scope string) string {
	if version == "" {
		version = DefaultVersion
	}
	fqn := fmt.Sprintf("%s.%s.v%s", RolePoliciesPrefix, sanitize(role), sanitize(version))
	return withScope(fqn, scope)
}

// RolePolicyModuleID returns the module ID for the role policies with the given scope.
func RolePolicyModuleID(role, version, scope string) ModuleID {
	return GenModuleIDFromFQN(RolePolicyFQN(role, version, scope))
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

// RuleFQN returns the FQN for the resource rule or principal resource action rule with scope granularity.
func RuleFQN(rpsMeta any, scope, ruleName string) string {
	var policyFqn string

	switch m := rpsMeta.(type) {
	case *runtimev1.RunnableResourcePolicySet_Metadata:
		policyFqn = ResourcePolicyFQN(m.Resource, m.Version, scope)
	case *runtimev1.RunnablePrincipalPolicySet_Metadata:
		policyFqn = PrincipalPolicyFQN(m.Principal, m.Version, scope)
	case *runtimev1.RuleTableMetadata:
		switch t := m.Name.(type) {
		case *runtimev1.RuleTableMetadata_Principal:
			policyFqn = PrincipalPolicyFQN(t.Principal, m.Version, scope)
		case *runtimev1.RuleTableMetadata_Resource:
			policyFqn = ResourcePolicyFQN(t.Resource, m.Version, scope)
		case *runtimev1.RuleTableMetadata_Role:
			policyFqn = RolePolicyFQN(t.Role, m.Version, scope)
		}
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
		return RolePolicyFQN(pc.Name, pc.Version, pc.Scope)
	default:
		panic(fmt.Errorf("unknown kind %q", pc.Kind))
	}
}

func (pc PolicyCoords) PolicyKey() string {
	return PolicyKeyFromFQN(pc.FQN())
}

func ScopeValue(scope string) string {
	return strings.TrimPrefix(scope, ".")
}

type Policy struct {
	PolicyCoords
	ID ModuleID
}
