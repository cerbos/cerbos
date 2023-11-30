// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
)

// Kind defines the type of policy (resource, principal, derived_roles etc.).
type Kind int

const (
	// ResourceKind points to a resource policy.
	ResourceKind Kind = iota
	PrincipalKind
	DerivedRolesKind
	ExportVariablesKind
)

const (
	ResourceKindStr        = "RESOURCE"
	PrincipalKindStr       = "PRINCIPAL"
	DerivedRolesKindStr    = "DERIVED_ROLES"
	ExportVariablesKindStr = "EXPORT_VARIABLES"
)

var IgnoreHashFields = map[string]struct{}{
	"cerbos.policy.v1.Policy.description": {},
	"cerbos.policy.v1.Policy.disabled":    {},
	"cerbos.policy.v1.Policy.json_schema": {},
	"cerbos.policy.v1.Policy.metadata":    {},
}

func (k Kind) String() string {
	switch k {
	case ResourceKind:
		return ResourceKindStr
	case PrincipalKind:
		return PrincipalKindStr
	case DerivedRolesKind:
		return DerivedRolesKindStr
	case ExportVariablesKind:
		return ExportVariablesKindStr
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
	case *policyv1.Policy_ExportVariables:
		return ExportVariablesKind
	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}
}

// KindFromFQN returns the kind of policy referred to by the given fully-qualified name.
func KindFromFQN(fqn string) Kind {
	switch {
	case strings.HasPrefix(fqn, namer.ResourcePoliciesPrefix):
		return ResourceKind
	case strings.HasPrefix(fqn, namer.PrincipalPoliciesPrefix):
		return PrincipalKind
	case strings.HasPrefix(fqn, namer.DerivedRolesPrefix):
		return DerivedRolesKind
	case strings.HasPrefix(fqn, namer.ExportVariablesPrefix):
		return ExportVariablesKind
	default:
		panic(fmt.Errorf("unknown policy FQN format %q", fqn))
	}
}

// Dependencies returns the module names of dependencies of the policy.
func Dependencies(p *policyv1.Policy) []string {
	var importDerivedRoles []string
	var importVariables []string

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		importDerivedRoles = pt.ResourcePolicy.ImportDerivedRoles
		importVariables = pt.ResourcePolicy.Variables.GetImport()

	case *policyv1.Policy_PrincipalPolicy:
		importVariables = pt.PrincipalPolicy.Variables.GetImport()

	case *policyv1.Policy_DerivedRoles:
		importVariables = pt.DerivedRoles.Variables.GetImport()

	case *policyv1.Policy_ExportVariables:

	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}

	dependencies := make([]string, 0, len(importDerivedRoles)+len(importVariables))

	for _, dr := range importDerivedRoles {
		dependencies = append(dependencies, namer.DerivedRolesFQN(dr))
	}

	for _, v := range importVariables {
		dependencies = append(dependencies, namer.ExportVariablesFQN(v))
	}

	return dependencies
}

// Ancestors returns the module IDs of the ancestors of this policy from most recent to oldest.
func Ancestors(p *policyv1.Policy) []namer.ModuleID {
	fqnTree := namer.FQNTree(p)
	n := len(fqnTree)

	// first element is the policy itself so we ignore that
	if n <= 1 {
		return nil
	}

	ancestors := make([]namer.ModuleID, n-1)
	for i, fqn := range fqnTree[1:] {
		ancestors[i] = namer.GenModuleIDFromFQN(fqn)
	}

	return ancestors
}

// RequiredAncestors returns the moduleID to FQN mapping of required ancestors of the policy.
func RequiredAncestors(p *policyv1.Policy) map[namer.ModuleID]string {
	fqnTree := namer.FQNTree(p)
	n := len(fqnTree)

	// first element is the policy itself so we ignore that
	if n <= 1 {
		return nil
	}

	ancestors := make(map[namer.ModuleID]string, n-1)
	for _, fqn := range fqnTree[1:] {
		ancestors[namer.GenModuleIDFromFQN(fqn)] = fqn
	}

	return ancestors
}

// SchemaReferences returns references to the schemas found in the policy.
func SchemaReferences(p *policyv1.Policy) []string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		schemas := pt.ResourcePolicy.Schemas
		if schemas == nil {
			return nil
		}

		var refs []string
		if schemas.PrincipalSchema != nil && schemas.PrincipalSchema.Ref != "" {
			refs = append(refs, schemas.PrincipalSchema.Ref)
		}

		if schemas.ResourceSchema != nil && schemas.ResourceSchema.Ref != "" {
			refs = append(refs, schemas.ResourceSchema.Ref)
		}

		return refs
	default:
		return nil
	}
}

func GetScope(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.Scope
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.Scope
	default:
		return ""
	}
}

// SourceAttribute holds structured information about the policy from its source.
type SourceAttribute struct {
	Value *structpb.Value
	Key   string
}

// SourceDriver creates a source attribute for the storage driver.
func SourceDriver(driver string) SourceAttribute {
	return SourceAttribute{Key: "driver", Value: structpb.NewStringValue(driver)}
}

// SourceFile creates a source attribute describing the file name of the policy.
func SourceFile(source string) SourceAttribute {
	return SourceAttribute{Key: "source", Value: structpb.NewStringValue(source)}
}

// WithSourceAttributes adds given source attributes to the policy.
func WithSourceAttributes(p *policyv1.Policy, attrs ...SourceAttribute) *policyv1.Policy {
	if p.Metadata == nil {
		p.Metadata = &policyv1.Metadata{}
	}

	if p.Metadata.SourceAttributes == nil {
		p.Metadata.SourceAttributes = &policyv1.SourceAttributes{
			Attributes: make(map[string]*structpb.Value, len(attrs)),
		}
	}

	for _, a := range attrs {
		p.Metadata.SourceAttributes.Attributes[a.Key] = a.Value
	}

	if p.Metadata.SourceFile != "" {
		p.Metadata.SourceAttributes.Attributes["source"] = structpb.NewStringValue(p.Metadata.SourceFile)
	}

	return p
}

// WithMetadata adds metadata to the policy.
func WithMetadata(p *policyv1.Policy, source string, annotations map[string]string, storeIdentifier string, sourceAttr ...SourceAttribute) *policyv1.Policy {
	if p.Metadata == nil {
		p.Metadata = &policyv1.Metadata{}
	}

	p.Metadata.SourceFile = source
	p.Metadata.Annotations = annotations
	p = WithSourceAttributes(p, sourceAttr...)

	if p.Metadata.StoreIdentifier == "" {
		p = WithStoreIdentifier(p, storeIdentifier)
	}

	if p.Metadata.Hash == nil {
		return WithHash(p)
	}

	return p
}

// WithStoreIdentifier adds the store identifier to the metadata.
func WithStoreIdentifier(p *policyv1.Policy, storeIdentifier string) *policyv1.Policy {
	if p.Metadata == nil {
		p.Metadata = &policyv1.Metadata{}
	}

	//nolint:staticcheck
	p.Metadata.StoreIdentifer = storeIdentifier // TODO: Remove this after deprecated StoreIdentifer no longer exists
	p.Metadata.StoreIdentifier = storeIdentifier

	return p
}

// WithHash calculates the hash for the policy and adds it to metadata.
func WithHash(p *policyv1.Policy) *policyv1.Policy {
	if p.Metadata == nil {
		p.Metadata = &policyv1.Metadata{}
	}

	p.Metadata.Hash = wrapperspb.UInt64(util.HashPB(p, IgnoreHashFields))

	return p
}

// GetHash returns the hash of the policy.
func GetHash(p *policyv1.Policy) uint64 {
	if p.Metadata == nil || p.Metadata.Hash == nil {
		p = WithHash(p)
	}

	return p.Metadata.Hash.GetValue()
}

// GetSourceFile gets the source file name from metadata if it exists.
func GetSourceFile(p *policyv1.Policy) string {
	if p == nil {
		return "unknown<nil>"
	}

	if p.Metadata != nil && p.Metadata.SourceFile != "" {
		return p.Metadata.SourceFile
	}

	return fmt.Sprintf("unknown<%s>", namer.FQN(p))
}

// Wrapper is a convenience layer over the policy definition.
type Wrapper struct {
	*policyv1.Policy
	FQN     string
	Name    string
	Version string
	Scope   string
	ID      namer.ModuleID
	Kind    Kind
}

// Wrap augments a policy with useful information about itself.
func Wrap(p *policyv1.Policy) Wrapper {
	w := Wrapper{Policy: p}

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		w.Kind = ResourceKind
		w.FQN = namer.ResourcePolicyFQN(pt.ResourcePolicy.Resource, pt.ResourcePolicy.Version, pt.ResourcePolicy.Scope)
		w.ID = namer.GenModuleIDFromFQN(w.FQN)
		w.Name = pt.ResourcePolicy.Resource
		w.Version = pt.ResourcePolicy.Version
		w.Scope = pt.ResourcePolicy.Scope

	case *policyv1.Policy_PrincipalPolicy:
		w.Kind = PrincipalKind
		w.FQN = namer.PrincipalPolicyFQN(pt.PrincipalPolicy.Principal, pt.PrincipalPolicy.Version, pt.PrincipalPolicy.Scope)
		w.ID = namer.GenModuleIDFromFQN(w.FQN)
		w.Name = pt.PrincipalPolicy.Principal
		w.Version = pt.PrincipalPolicy.Version
		w.Scope = pt.PrincipalPolicy.Scope

	case *policyv1.Policy_DerivedRoles:
		w.Kind = DerivedRolesKind
		w.FQN = namer.DerivedRolesFQN(pt.DerivedRoles.Name)
		w.ID = namer.GenModuleIDFromFQN(w.FQN)
		w.Name = pt.DerivedRoles.Name

	case *policyv1.Policy_ExportVariables:
		w.Kind = ExportVariablesKind
		w.FQN = namer.ExportVariablesFQN(pt.ExportVariables.Name)
		w.ID = namer.GenModuleIDFromFQN(w.FQN)
		w.Name = pt.ExportVariables.Name

	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}

	return w
}

func (pw Wrapper) Dependencies() []namer.ModuleID {
	fqns := Dependencies(pw.Policy)
	modIDs := make([]namer.ModuleID, len(fqns))
	for i, fqn := range fqns {
		modIDs[i] = namer.GenModuleIDFromFQN(fqn)
	}
	return modIDs
}

// CompilationUnit is the set of policies that need to be compiled together.
// For example, if a resource policy named R imports derived roles named D, the compilation unit will contain
// both R and D with the ModID field pointing to R because it is the main policy.
type CompilationUnit struct {
	Definitions map[namer.ModuleID]*policyv1.Policy
	ModID       namer.ModuleID
}

func (cu *CompilationUnit) AddDefinition(id namer.ModuleID, p *policyv1.Policy) {
	if cu.Definitions == nil {
		cu.Definitions = make(map[namer.ModuleID]*policyv1.Policy)
	}

	cu.Definitions[id] = p
}

func (cu *CompilationUnit) MainSourceFile() string {
	return GetSourceFile(cu.Definitions[cu.ModID])
}

func (cu *CompilationUnit) MainPolicy() *policyv1.Policy {
	return cu.Definitions[cu.ModID]
}

func (cu *CompilationUnit) Ancestors() []namer.ModuleID {
	return Ancestors(cu.Definitions[cu.ModID])
}

// Key returns the human readable identifier for the main module.
func (cu *CompilationUnit) Key() string {
	return namer.PolicyKey(cu.Definitions[cu.ModID])
}
