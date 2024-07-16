// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/util"
)

// Kind defines the type of policy (resource, principal, derived_roles etc.).
type Kind policyv1.Kind

const (
	DerivedRolesKind    Kind = Kind(policyv1.Kind_KIND_DERIVED_ROLES)
	ExportVariablesKind Kind = Kind(policyv1.Kind_KIND_EXPORT_VARIABLES)
	PrincipalKind       Kind = Kind(policyv1.Kind_KIND_PRINCIPAL)
	ResourceKind        Kind = Kind(policyv1.Kind_KIND_RESOURCE)
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
func Dependencies(p *policyv1.Policy) ([]string, []string) {
	var importDerivedRoles []string
	var importVariables []string
	var importVariablesProtoPath string

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		importDerivedRoles = pt.ResourcePolicy.ImportDerivedRoles
		importVariables = pt.ResourcePolicy.Variables.GetImport()
		importVariablesProtoPath = "resource_policy.variables.import"

	case *policyv1.Policy_PrincipalPolicy:
		importVariables = pt.PrincipalPolicy.Variables.GetImport()
		importVariablesProtoPath = "principal_policy.variables.import"

	case *policyv1.Policy_DerivedRoles:
		importVariables = pt.DerivedRoles.Variables.GetImport()
		importVariablesProtoPath = "derived_roles.variables.import"

	case *policyv1.Policy_ExportVariables:

	default:
		panic(fmt.Errorf("unknown policy type %T", pt))
	}

	dependencies := make([]string, 0, len(importDerivedRoles)+len(importVariables))
	paths := make([]string, 0, len(dependencies))

	for i, dr := range importDerivedRoles {
		dependencies = append(dependencies, namer.DerivedRolesFQN(dr))
		paths = append(paths, fmt.Sprintf("resource_policy.import_derived_roles[%d]", i))
	}

	for i, v := range importVariables {
		dependencies = append(dependencies, namer.ExportVariablesFQN(v))
		paths = append(paths, fmt.Sprintf("%s[%d]", importVariablesProtoPath, i))
	}

	return dependencies, paths
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

// SourceUpdateTS creates a source attribute describing the time a policy was updated in a mutable store.
func SourceUpdateTS(timestamp time.Time) SourceAttribute {
	return SourceAttribute{Key: "update_ts", Value: structpb.NewStringValue(timestamp.Format(time.RFC3339))}
}

// SourceUpdateTSNow creates a source attribute setting the update time to now.
func SourceUpdateTSNow() SourceAttribute {
	return SourceUpdateTS(time.Now())
}

// WithSourceAttributes adds given source attributes to the policy.
func WithSourceAttributes(p *policyv1.Policy, attrs ...SourceAttribute) *policyv1.Policy {
	if p.Metadata == nil {
		p.Metadata = &policyv1.Metadata{
			SourceAttributes: &policyv1.SourceAttributes{
				Attributes: make(map[string]*structpb.Value, len(attrs)),
			},
		}
	}

	if p.Metadata.SourceAttributes == nil {
		p.Metadata.SourceAttributes = &policyv1.SourceAttributes{
			Attributes: make(map[string]*structpb.Value, len(attrs)),
		}
	}

	if p.Metadata.SourceAttributes.Attributes == nil {
		p.Metadata.SourceAttributes.Attributes = make(map[string]*structpb.Value, len(attrs))
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
	p.Metadata.Annotations = mergeAnnotations(p.Metadata.Annotations, annotations)
	p = WithSourceAttributes(p, sourceAttr...)

	if p.Metadata.StoreIdentifier == "" {
		p = WithStoreIdentifier(p, storeIdentifier)
	}

	if p.Metadata.Hash == nil {
		return WithHash(p)
	}

	return p
}

func mergeAnnotations(a, b map[string]string) map[string]string {
	if a == nil {
		return b
	}

	if b == nil {
		return a
	}

	c := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		c[k] = v
	}
	for k, v := range b {
		c[k] = v
	}
	return c
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
		return "<>"
	}

	if p.Metadata != nil && p.Metadata.SourceFile != "" {
		return p.Metadata.SourceFile
	}

	return fmt.Sprintf("<%s>", namer.PolicyKey(p))
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

// ListActions returns unique list of actions in a policy.
func ListActions(p *policyv1.Policy) []string {
	var actions []string
	if p == nil {
		return actions
	}

	ss := make(util.StringSet)
	switch p := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		for _, r := range p.ResourcePolicy.Rules {
			for _, a := range r.Actions {
				if !ss.Contains(a) {
					ss[a] = struct{}{}
					actions = append(actions, a)
				}
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		for _, r := range p.PrincipalPolicy.Rules {
			for _, a := range r.Actions {
				if !ss.Contains(a.Action) {
					ss[a.Action] = struct{}{}
					actions = append(actions, a.Action)
				}
			}
		}
	}

	return actions
}

// ListExportedDerivedRoles returns exported derived roles defined in the given derived roles policy.
func ListExportedDerivedRoles(drp *policyv1.DerivedRoles) []*responsev1.InspectPoliciesResponse_DerivedRole {
	var derivedRoles []*responsev1.InspectPoliciesResponse_DerivedRole
	if drp == nil {
		return derivedRoles
	}

	ss := make(util.StringSet)
	for _, dr := range drp.Definitions {
		if !ss.Contains(dr.Name) {
			ss[dr.Name] = struct{}{}
			derivedRoles = append(derivedRoles, &responsev1.InspectPoliciesResponse_DerivedRole{
				Name:   dr.Name,
				Kind:   responsev1.InspectPoliciesResponse_DerivedRole_KIND_EXPORTED,
				Source: namer.PolicyKeyFromFQN(namer.DerivedRolesFQN(drp.Name)),
			})
		}
	}

	return derivedRoles
}

// ListVariables returns local and exported variables (not imported ones) defined in a policy.
func ListVariables(p *policyv1.Policy) map[string]*responsev1.InspectPoliciesResponse_Variable {
	variables := make(map[string]*responsev1.InspectPoliciesResponse_Variable)
	if p == nil {
		return variables
	}
	policyKey := namer.PolicyKey(p)

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_DerivedRoles:
		if pt.DerivedRoles.Variables == nil {
			return variables
		}

		for name, value := range pt.DerivedRoles.Variables.Local {
			variables[name] = &responsev1.InspectPoliciesResponse_Variable{
				Name:   name,
				Value:  value,
				Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL,
				Source: policyKey,
			}
		}
	case *policyv1.Policy_ExportVariables:
		for name, value := range pt.ExportVariables.Definitions {
			variables[name] = &responsev1.InspectPoliciesResponse_Variable{
				Name:   name,
				Value:  value,
				Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_EXPORTED,
				Source: policyKey,
			}
		}
	case *policyv1.Policy_PrincipalPolicy:
		if pt.PrincipalPolicy.Variables == nil {
			return variables
		}

		for name, value := range pt.PrincipalPolicy.Variables.Local {
			variables[name] = &responsev1.InspectPoliciesResponse_Variable{
				Name:   name,
				Value:  value,
				Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL,
				Source: policyKey,
			}
		}
	case *policyv1.Policy_ResourcePolicy:
		if pt.ResourcePolicy.Variables == nil {
			return variables
		}

		for name, value := range pt.ResourcePolicy.Variables.Local {
			variables[name] = &responsev1.InspectPoliciesResponse_Variable{
				Name:   name,
				Value:  value,
				Kind:   responsev1.InspectPoliciesResponse_Variable_KIND_LOCAL,
				Source: policyKey,
			}
		}
	}

	return variables
}

// ListPolicySetActions returns unique list of actions in a policy set.
func ListPolicySetActions(ps *runtimev1.RunnablePolicySet) []string {
	var actions []string
	if ps == nil {
		return actions
	}

	ss := make(util.StringSet)
	switch set := ps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		for _, p := range set.ResourcePolicy.Policies {
			for _, r := range p.Rules {
				for a := range r.Actions {
					if !ss.Contains(a) {
						ss[a] = struct{}{}
						actions = append(actions, a)
					}
				}
			}
		}
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, p := range set.PrincipalPolicy.Policies {
			for _, r := range p.ResourceRules {
				for _, ar := range r.ActionRules {
					if !ss.Contains(ar.Action) {
						ss[ar.Action] = struct{}{}
						actions = append(actions, ar.Action)
					}
				}
			}
		}
	}

	return actions
}

// ListPolicySetDerivedRoles returns imported and used derived roles defined in a policy set.
func ListPolicySetDerivedRoles(ps *runtimev1.RunnablePolicySet) []*responsev1.InspectPoliciesResponse_DerivedRole {
	if ps == nil {
		return nil
	}

	var rp *runtimev1.RunnablePolicySet_ResourcePolicy
	var ok bool
	if rp, ok = ps.PolicySet.(*runtimev1.RunnablePolicySet_ResourcePolicy); !ok {
		return nil
	}

	available := make(util.StringSet)
	referenced := make(util.StringSet)
	for _, p := range rp.ResourcePolicy.Policies {
		for _, dr := range p.DerivedRoles {
			if !available.Contains(dr.Name) {
				available[dr.Name] = struct{}{}
			}
		}

		for _, r := range p.Rules {
			for derivedRole := range r.DerivedRoles {
				if available.Contains(derivedRole) {
					referenced[derivedRole] = struct{}{}
				}
			}
		}
	}

	derivedRoles := make([]*responsev1.InspectPoliciesResponse_DerivedRole, 0, len(referenced))
	for derivedRole := range referenced {
		derivedRoles = append(derivedRoles, &responsev1.InspectPoliciesResponse_DerivedRole{
			Name: derivedRole,
			Kind: responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED,
		})
	}

	return derivedRoles
}

// ListPolicySetVariables returns local and exported variables defined in a policy set.
func ListPolicySetVariables(ps *runtimev1.RunnablePolicySet) []*responsev1.InspectPoliciesResponse_Variable {
	var variables []*responsev1.InspectPoliciesResponse_Variable
	if ps == nil {
		return variables
	}

	switch set := ps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, p := range set.PrincipalPolicy.Policies {
			for _, variable := range p.OrderedVariables {
				variables = append(variables, &responsev1.InspectPoliciesResponse_Variable{
					Name:  variable.Name,
					Value: variable.Expr.Original,
					Kind:  responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN,
					Used:  true,
				})
			}
		}
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		for _, p := range set.ResourcePolicy.Policies {
			for _, variable := range p.OrderedVariables {
				variables = append(variables, &responsev1.InspectPoliciesResponse_Variable{
					Name:  variable.Name,
					Value: variable.Expr.Original,
					Kind:  responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN,
					Used:  true,
				})
			}
		}
	}

	return variables
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

func (w Wrapper) Dependencies() []namer.ModuleID {
	fqns, _ := Dependencies(w.Policy)
	modIDs := make([]namer.ModuleID, len(fqns))
	for i, fqn := range fqns {
		modIDs[i] = namer.GenModuleIDFromFQN(fqn)
	}
	return modIDs
}

func (w Wrapper) ToProto() *sourcev1.PolicyWrapper {
	return &sourcev1.PolicyWrapper{
		Id:      w.ID.RawValue(),
		Key:     namer.PolicyKeyFromFQN(w.FQN),
		Policy:  w.Policy,
		Kind:    policyv1.Kind(w.Kind),
		Name:    w.Name,
		Version: w.Version,
		Scope:   w.Scope,
	}
}

// CompilationUnit is the set of policies that need to be compiled together.
// For example, if a resource policy named R imports derived roles named D, the compilation unit will contain
// both R and D with the ModID field pointing to R because it is the main policy.
type CompilationUnit struct {
	Definitions    map[namer.ModuleID]*policyv1.Policy
	SourceContexts map[namer.ModuleID]parser.SourceCtx
	ModID          namer.ModuleID
}

func (cu *CompilationUnit) AddDefinition(id namer.ModuleID, p *policyv1.Policy, sc parser.SourceCtx) {
	if cu.Definitions == nil {
		cu.Definitions = make(map[namer.ModuleID]*policyv1.Policy)
	}

	if cu.SourceContexts == nil {
		cu.SourceContexts = make(map[namer.ModuleID]parser.SourceCtx)
	}

	cu.Definitions[id] = p
	cu.SourceContexts[id] = sc
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
