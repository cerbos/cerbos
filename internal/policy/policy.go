// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

// Kind defines the type of policy (resource, principal, derived_roles etc.).
type Kind int

const (
	// ResourceKind points to a resource policy.
	ResourceKind Kind = iota
	PrincipalKind
	DerivedRolesKind
)

const (
	ResourceKindStr     = "RESOURCE"
	PrincipalKindStr    = "PRINCIPAL"
	DerivedRolesKindStr = "DERIVED_ROLES"
)

func (k Kind) String() string {
	switch k {
	case ResourceKind:
		return ResourceKindStr
	case PrincipalKind:
		return PrincipalKindStr
	case DerivedRolesKind:
		return DerivedRolesKindStr
	default:
		panic(fmt.Errorf("unknown policy kind %d", k))
	}
}

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

// WithMetadata adds metadata to the policy.
func WithMetadata(p *policyv1.Policy, source string, annotations map[string]string) *policyv1.Policy {
	if p.Metadata == nil {
		p.Metadata = &policyv1.Metadata{}
	}

	p.Metadata.SourceFile = source
	p.Metadata.Annotations = annotations

	return p
}

// GetSourceFile gets the source file name from metadata if it exists.
func GetSourceFile(p *policyv1.Policy) string {
	if p == nil {
		return "unknown<nil>"
	}

	if p.Metadata != nil && p.Metadata.SourceFile != "" {
		return p.Metadata.SourceFile
	}

	return fmt.Sprintf("unknown<%s>", namer.ModuleName(p))
}

// Wrapper is a convenience layer over the policy definition.
type Wrapper struct {
	ID           namer.ModuleID
	FQN          string
	Kind         string
	Name         string
	Version      string
	Dependencies []namer.ModuleID
	*policyv1.Policy
}

func Wrap(p *policyv1.Policy) Wrapper {
	w := Wrapper{Policy: p}

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		w.Kind = ResourceKind.String()
		w.FQN = namer.ResourcePolicyModuleName(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version)
		w.ID = namer.GenModuleIDFromName(w.FQN)
		w.Name = pt.ResourcePolicy.Resource
		w.Version = pt.ResourcePolicy.Version

		imports := pt.ResourcePolicy.ImportDerivedRoles
		if len(imports) > 0 {
			w.Dependencies = make([]namer.ModuleID, len(imports))
			for i, imp := range imports {
				w.Dependencies[i] = namer.GenModuleIDFromName(namer.DerivedRolesModuleName(imp))
			}
		}

	case *policyv1.Policy_PrincipalPolicy:
		w.Kind = PrincipalKind.String()
		w.FQN = namer.PrincipalPolicyModuleName(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version)
		w.ID = namer.GenModuleIDFromName(w.FQN)
		w.Name = pt.PrincipalPolicy.Principal
		w.Version = pt.PrincipalPolicy.Version

	case *policyv1.Policy_DerivedRoles:
		w.Kind = DerivedRolesKind.String()
		w.FQN = namer.DerivedRolesModuleName(pt.DerivedRoles.Name)
		w.ID = namer.GenModuleIDFromName(w.FQN)
		w.Name = pt.DerivedRoles.Name

	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}

	return w
}

// CompilationUnit is the set of policies that need to be compiled together.
// For example, if a resource policy named R imports derived roles named D, the compilation unit will contain
// both R and D with the ModID field pointing to R because it is the main policy.
type CompilationUnit struct {
	ModID       namer.ModuleID
	Definitions map[namer.ModuleID]*policyv1.Policy
	Generated   map[namer.ModuleID]*policyv1.GeneratedPolicy
}

func (cu *CompilationUnit) AddDefinition(id namer.ModuleID, p *policyv1.Policy) {
	if cu.Definitions == nil {
		cu.Definitions = make(map[namer.ModuleID]*policyv1.Policy)
	}

	cu.Definitions[id] = p
}

func (cu *CompilationUnit) AddGenerated(id namer.ModuleID, p *policyv1.GeneratedPolicy) {
	if cu.Generated == nil {
		cu.Generated = make(map[namer.ModuleID]*policyv1.GeneratedPolicy)
	}

	cu.Generated[id] = p
}

func (cu *CompilationUnit) MainSourceFile() string {
	return GetSourceFile(cu.Definitions[cu.ModID])
}

// Query returns the query that is expected to be evaluated from this policy set.
func (cu *CompilationUnit) Query() string {
	main := cu.Definitions[cu.ModID]

	switch pt := main.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return namer.QueryForResource(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version)
	case *policyv1.Policy_PrincipalPolicy:
		return namer.QueryForPrincipal(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version)
	case *policyv1.Policy_DerivedRoles:
		return ""
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

// Key returns the human readable identifier for the main module.
func (cu *CompilationUnit) Key() string {
	return namer.PolicyKey(cu.Definitions[cu.ModID])
}
