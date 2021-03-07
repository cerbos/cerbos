package policy

import (
	"fmt"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/namer"
)

// Kind defines the type of policy (resource, principal, derived_roles etc.).
type Kind int

const (
	ResourceKind Kind = iota
	PrincipalKind
	DerivedRolesKind
)

// GetKind returns the kind of the given policy.
func GetKind(p *policyv1.Policy) Kind {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return ResourceKind
	case *policyv1.Policy_PrincipalPolicy:
		return PrincipalKind
	case *policyv1.Policy_DerivedRoles:
		return DerivedRolesKind
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

// Dependencies returns the module names of dependencies of the policy.
func Dependencies(p *policyv1.Policy) []string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		imports := pt.ResourcePolicy.ImportDerivedRoles
		if len(imports) == 0 {
			return nil
		}

		dr := make([]string, len(imports))
		for i, imp := range imports {
			dr[i] = namer.DerivedRolesModuleName(imp)
		}

		return dr
	default:
		return nil
	}
}

// InitGlobal creates a new registry, registers it with OPA runtime and returns the instance.
func InitGlobal() Registry {
	reg := NewRegistry()
	InitRego(reg)

	return reg
}
