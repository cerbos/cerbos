// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

type compilerVersionMigration func(*runtimev1.RuleTable) error

var (
	compilerVersionMigrations = []compilerVersionMigration{
		migrateFromCompilerVersion0To1,
	}

	compilerVersion = uint32(len(compilerVersionMigrations))
)

const (
	conditionNotSatisfied   = "Condition not satisfied"
	noMatchScopePermissions = "NO_MATCH_FOR_SCOPE_PERMISSIONS"
	noPolicyMatch           = "NO_MATCH"
)

func NewProtoRuletable() *runtimev1.RuleTable {
	return &runtimev1.RuleTable{
		Rules:              []*runtimev1.RuleTable_RuleRow{},
		Schemas:            make(map[uint64]*policyv1.Schemas),
		Meta:               make(map[uint64]*runtimev1.RuleTableMetadata),
		ScopeParentRoles:   make(map[string]*runtimev1.RuleTable_RoleParentRoles),
		PolicyDerivedRoles: make(map[uint64]*runtimev1.RuleTable_PolicyDerivedRoles),
		JsonSchemas:        make(map[string]*runtimev1.RuleTable_JSONSchema),
		CompilerVersion:    compilerVersion,
	}
}

func LoadPolicies(ctx context.Context, rt *runtimev1.RuleTable, pl policyloader.PolicyLoader) error {
	rps, err := pl.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to get all policies: %w", err)
	}

	m := make([][]*runtimev1.RuleTable_RuleRow, 0, len(rps))
	total := 0
	for _, p := range rps {
		rules := AddPolicy(rt, p)
		m = append(m, rules)
		total += len(rules)
	}

	rt.Rules = make([]*runtimev1.RuleTable_RuleRow, 0, total)
	for _, rules := range m {
		rt.Rules = append(rt.Rules, rules...)
	}

	return nil
}

func LoadSchemas(ctx context.Context, rt *runtimev1.RuleTable, sl schema.Loader) error {
	if err := buildRawSchemas(ctx, rt, schema.StaticResolver(sl)); err != nil {
		return err
	}

	return nil
}

func AddPolicy(rt *runtimev1.RuleTable, rps *runtimev1.RunnablePolicySet) []*runtimev1.RuleTable_RuleRow {
	switch rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		return addResourcePolicy(rt, rps.GetResourcePolicy())
	case *runtimev1.RunnablePolicySet_RolePolicy:
		return addRolePolicy(rt, rps.GetRolePolicy())
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		return addPrincipalPolicy(rt, rps.GetPrincipalPolicy())
	}

	return nil
}

func addPrincipalPolicy(rt *runtimev1.RuleTable, rpps *runtimev1.RunnablePrincipalPolicySet) (res []*runtimev1.RuleTable_RuleRow) {
	principalID := rpps.Meta.Principal

	policies := rpps.GetPolicies()
	if len(policies) == 0 {
		return res
	}

	// We only process the first of principal policy sets as it's assumed parent scopes are handled in separate calls
	p := policies[0]

	moduleID := namer.GenModuleIDFromFQN(rpps.Meta.Fqn)
	rt.Meta[moduleID.RawValue()] = &runtimev1.RuleTableMetadata{
		Fqn:              rpps.Meta.Fqn,
		Name:             &runtimev1.RuleTableMetadata_Principal{Principal: principalID},
		Version:          rpps.Meta.Version,
		SourceAttributes: rpps.Meta.SourceAttributes,
		Annotations:      rpps.Meta.Annotations,
	}

	scopePermissions := p.ScopePermissions
	if scopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
		scopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
	}

	if len(p.ResourceRules) == 0 {
		// Cover the edge case where a policy is created with no rules (useful in the multitenant case
		// where a tenant might want to "inherit" the permissions of the parent by immediately falling
		// through). We do this by creating a noop row in the rule table which means we bypass the
		// "policy does not exist in the scope" during evaluation.
		res = append(res, &runtimev1.RuleTable_RuleRow{
			OriginFqn:         rpps.Meta.Fqn,
			Scope:             p.Scope,
			ScopePermissions:  scopePermissions,
			Version:           rpps.Meta.Version,
			Principal:         principalID,
			PolicyKind:        policyv1.Kind_KIND_PRINCIPAL,
			Params:            &runtimev1.RuleTable_RuleRow_Params{},
			DerivedRoleParams: &runtimev1.RuleTable_RuleRow_Params{},
		})
	}

	for resource, resourceRules := range p.ResourceRules {
		for _, rule := range resourceRules.ActionRules {
			emitOutput := rule.EmitOutput
			if emitOutput == nil && rule.Output != nil { //nolint:staticcheck
				emitOutput = &runtimev1.Output{
					When: &runtimev1.Output_When{
						RuleActivated: rule.Output, //nolint:staticcheck
					},
				}
			}

			ruleFqn := namer.RuleFQN(rt.Meta[moduleID.RawValue()], p.Scope, rule.Name)
			evaluationKey := fmt.Sprintf("%s#%s", namer.PrincipalPolicyFQN(principalID, rpps.Meta.Version, p.Scope), ruleFqn)

			row := &runtimev1.RuleTable_RuleRow{
				OriginFqn: rpps.Meta.Fqn,
				Resource:  namer.SanitizedResource(resource),
				// Since principal policies don't have explicit roles, we use "*" to match any role
				Role: "*",
				ActionSet: &runtimev1.RuleTable_RuleRow_Action{
					Action: rule.Action,
				},
				Condition:        rule.Condition,
				Effect:           rule.Effect,
				Scope:            p.Scope,
				ScopePermissions: scopePermissions,
				Version:          rpps.Meta.Version,
				EmitOutput:       emitOutput,
				Name:             rule.Name,
				Principal:        principalID,
				Params: &runtimev1.RuleTable_RuleRow_Params{
					OrderedVariables: p.OrderedVariables,
					Constants:        p.Constants,
				},
				EvaluationKey: evaluationKey,
				PolicyKind:    policyv1.Kind_KIND_PRINCIPAL,
			}

			if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS &&
				row.Effect == effectv1.Effect_EFFECT_ALLOW &&
				row.Condition != nil {
				row.Condition = &runtimev1.Condition{
					Op: &runtimev1.Condition_None{
						None: &runtimev1.Condition_ExprList{
							Expr: []*runtimev1.Condition{row.Condition},
						},
					},
				}
				row.Effect = effectv1.Effect_EFFECT_DENY
			}

			res = append(res, row)
		}
	}

	return res
}

func addResourcePolicy(rt *runtimev1.RuleTable, rrps *runtimev1.RunnableResourcePolicySet) (res []*runtimev1.RuleTable_RuleRow) {
	sanitizedResource := namer.SanitizedResource(rrps.Meta.Resource)

	policies := rrps.GetPolicies()
	if len(policies) == 0 {
		return res
	}

	// we only process the first of resource policy sets as it's assumed parent scopes are handled in separate calls
	p := rrps.GetPolicies()[0]

	moduleID := namer.GenModuleIDFromFQN(rrps.Meta.Fqn)
	if rrps.Schemas != nil {
		rt.Schemas[moduleID.RawValue()] = rrps.Schemas
	}
	rt.Meta[moduleID.RawValue()] = &runtimev1.RuleTableMetadata{
		Fqn:              rrps.Meta.Fqn,
		Name:             &runtimev1.RuleTableMetadata_Resource{Resource: sanitizedResource},
		Version:          rrps.Meta.Version,
		SourceAttributes: rrps.Meta.SourceAttributes,
		Annotations:      rrps.Meta.Annotations,
	}

	if len(p.DerivedRoles) > 0 {
		rt.PolicyDerivedRoles[moduleID.RawValue()] = &runtimev1.RuleTable_PolicyDerivedRoles{DerivedRoles: p.DerivedRoles}
	}

	scopePermissions := p.ScopePermissions
	if scopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
		scopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
	}

	if len(p.Rules) == 0 {
		// Cover the edge case where a policy is created with no rules (useful in the multitenant case
		// where a tenant might want to "inherit" the permissions of the parent by immediately falling
		// through). We do this by creating a noop row in the rule table which means we bypass the
		// "policy does not exist in the scope" during evaluation.
		res = append(res, &runtimev1.RuleTable_RuleRow{
			OriginFqn:         rrps.Meta.Fqn,
			Resource:          sanitizedResource,
			Scope:             p.Scope,
			ScopePermissions:  scopePermissions,
			Version:           rrps.Meta.Version,
			PolicyKind:        policyv1.Kind_KIND_RESOURCE,
			Params:            &runtimev1.RuleTable_RuleRow_Params{},
			DerivedRoleParams: &runtimev1.RuleTable_RuleRow_Params{},
		})
	}

	for _, rule := range p.Rules {
		emitOutput := rule.EmitOutput
		if emitOutput == nil && rule.Output != nil { //nolint:staticcheck
			emitOutput = &runtimev1.Output{
				When: &runtimev1.Output_When{
					RuleActivated: rule.Output, //nolint:staticcheck
				},
			}
		}

		ruleFqn := namer.RuleFQN(rt.Meta[moduleID.RawValue()], p.Scope, rule.Name)
		evaluationKey := fmt.Sprintf("%s#%s", namer.ResourcePolicyFQN(sanitizedResource, rrps.Meta.Version, p.Scope), ruleFqn)
		for a := range rule.Actions {
			for r := range rule.Roles {
				row := &runtimev1.RuleTable_RuleRow{
					OriginFqn: rrps.Meta.Fqn,
					Resource:  sanitizedResource,
					Role:      r,
					ActionSet: &runtimev1.RuleTable_RuleRow_Action{
						Action: a,
					},
					Condition:        rule.Condition,
					Effect:           rule.Effect,
					Scope:            p.Scope,
					ScopePermissions: scopePermissions,
					Version:          rrps.Meta.Version,
					EmitOutput:       emitOutput,
					Name:             rule.Name,
					Params: &runtimev1.RuleTable_RuleRow_Params{
						OrderedVariables: p.OrderedVariables,
						Constants:        p.Constants,
					},
					EvaluationKey: evaluationKey,
					PolicyKind:    policyv1.Kind_KIND_RESOURCE,
				}

				if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS &&
					row.Effect == effectv1.Effect_EFFECT_ALLOW &&
					row.Condition != nil {
					row.Condition = &runtimev1.Condition{
						Op: &runtimev1.Condition_None{
							None: &runtimev1.Condition_ExprList{
								Expr: []*runtimev1.Condition{row.Condition},
							},
						},
					}
					row.Effect = effectv1.Effect_EFFECT_DENY
				}

				res = append(res, row)
			}

			// merge derived roles as roles with added conditions
			for dr := range rule.DerivedRoles {
				if rdr, ok := p.DerivedRoles[dr]; ok {
					evaluationKey := fmt.Sprintf("%s#%s", namer.DerivedRolesFQN(dr), ruleFqn)
					for pr := range rdr.ParentRoles {
						row := &runtimev1.RuleTable_RuleRow{
							OriginFqn: rrps.Meta.Fqn,
							Resource:  sanitizedResource,
							Role:      pr,
							ActionSet: &runtimev1.RuleTable_RuleRow_Action{
								Action: a,
							},
							Condition:            rule.Condition,
							DerivedRoleCondition: rdr.Condition,
							Effect:               rule.Effect,
							Scope:                p.Scope,
							ScopePermissions:     scopePermissions,
							Version:              rrps.Meta.Version,
							OriginDerivedRole:    dr,
							EmitOutput:           emitOutput,
							Name:                 rule.Name,
							Params: &runtimev1.RuleTable_RuleRow_Params{
								OrderedVariables: p.OrderedVariables,
								Constants:        p.Constants,
							},
							DerivedRoleParams: &runtimev1.RuleTable_RuleRow_Params{
								OrderedVariables: rdr.OrderedVariables,
								Constants:        rdr.Constants,
							},
							EvaluationKey: evaluationKey,
							PolicyKind:    policyv1.Kind_KIND_RESOURCE,
						}

						if p.ScopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS &&
							row.Effect == effectv1.Effect_EFFECT_ALLOW &&
							row.Condition != nil {
							row.Condition = &runtimev1.Condition{
								Op: &runtimev1.Condition_None{
									None: &runtimev1.Condition_ExprList{
										Expr: []*runtimev1.Condition{row.Condition},
									},
								},
							}
							row.Effect = effectv1.Effect_EFFECT_DENY
						}

						res = append(res, row)
					}
				}
			}
		}
	}

	return res
}

func addRolePolicy(rt *runtimev1.RuleTable, p *runtimev1.RunnableRolePolicySet) (res []*runtimev1.RuleTable_RuleRow) {
	moduleID := namer.GenModuleIDFromFQN(p.Meta.Fqn)
	rt.Meta[moduleID.RawValue()] = &runtimev1.RuleTableMetadata{
		Fqn:              p.Meta.Fqn,
		Name:             &runtimev1.RuleTableMetadata_Role{Role: p.Role},
		Version:          p.Meta.Version,
		SourceAttributes: p.Meta.SourceAttributes,
		Annotations:      p.Meta.Annotations,
	}
	for resource, rl := range p.Resources {
		for idx, rule := range rl.Rules {
			res = append(res, &runtimev1.RuleTable_RuleRow{
				OriginFqn: p.Meta.Fqn,
				Role:      p.Role,
				Resource:  resource,
				ActionSet: &runtimev1.RuleTable_RuleRow_AllowActions_{
					AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
						Actions: rule.AllowActions,
					},
				},
				Condition:  rule.Condition,
				EmitOutput: rule.EmitOutput,
				Name:       rule.Name,
				Scope:      p.Scope,
				Version:    p.Meta.Version,
				Params: &runtimev1.RuleTable_RuleRow_Params{
					OrderedVariables: p.OrderedVariables,
					Constants:        p.Constants,
				},
				EvaluationKey:  fmt.Sprintf("%s#%s_rule-%03d", namer.PolicyKeyFromFQN(namer.RolePolicyFQN(p.Role, p.Meta.Version, p.Scope)), p.Role, idx),
				PolicyKind:     policyv1.Kind_KIND_RESOURCE,
				FromRolePolicy: true,
			})
		}
	}

	if _, ok := rt.ScopeParentRoles[p.Scope]; !ok {
		rt.ScopeParentRoles[p.Scope] = &runtimev1.RuleTable_RoleParentRoles{
			RoleParentRoles: make(map[string]*runtimev1.RuleTable_RoleParentRoles_ParentRoles),
		}
	}

	rt.ScopeParentRoles[p.Scope].RoleParentRoles[p.Role] = &runtimev1.RuleTable_RoleParentRoles_ParentRoles{
		Roles: p.ParentRoles,
	}

	return res
}

func buildRawSchemas(ctx context.Context, rt *runtimev1.RuleTable, resolver schema.Resolver) error {
	for _, s := range rt.Schemas {
		for _, r := range []string{s.GetPrincipalSchema().GetRef(), s.GetResourceSchema().GetRef()} {
			if r != "" {
				rc, err := resolver(ctx, r)
				if err != nil {
					return err
				}

				schBytes, err := io.ReadAll(rc)
				if err != nil {
					return err
				}

				rt.JsonSchemas[r] = &runtimev1.RuleTable_JSONSchema{
					Content: schBytes,
				}
			}
		}
	}
	return nil
}

type RuleTable struct {
	*runtimev1.RuleTable
	idx                   *index.Index
	principalScopeMap     map[string]struct{}
	resourceScopeMap      map[string]struct{}
	scopeScopePermissions map[string]policyv1.ScopePermissions
	policyDerivedRoles    map[namer.ModuleID]map[string]*WrappedRunnableDerivedRole
	programCache          *ProgramCache
}

type WrappedRunnableDerivedRole struct {
	*runtimev1.RunnableDerivedRole
	Constants   map[string]any
	VarCacheKey uint64
}

// ProgramCache caches compiled CEL programs keyed by CheckedExpr pointer to avoid repeated compilation.
// Programs are compiled with CacheFriendlyTimeDecorator which looks up NowFunc from activation at eval time.
type ProgramCache struct {
	m  map[*exprpb.CheckedExpr]cel.Program
	mu sync.RWMutex
}

func NewProgramCache() *ProgramCache {
	return &ProgramCache{
		m: make(map[*exprpb.CheckedExpr]cel.Program),
	}
}

func (c *ProgramCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
}

func (c *ProgramCache) GetOrCreate(expr *exprpb.CheckedExpr) (cel.Program, error) {
	if c == nil {
		return conditions.StdEnv.Program(
			cel.CheckedExprToAst(expr),
			cel.CustomDecorator(conditions.CacheFriendlyTimeDecorator()),
		)
	}

	c.mu.RLock()
	if prg, ok := c.m[expr]; ok {
		c.mu.RUnlock()
		return prg, nil
	}
	c.mu.RUnlock()

	prg, err := conditions.StdEnv.Program(
		cel.CheckedExprToAst(expr),
		cel.CustomDecorator(conditions.CacheFriendlyTimeDecorator()),
	)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.m[expr] = prg
	c.mu.Unlock()
	return prg, nil
}

func NewRuleTableFromLoader(ctx context.Context, policyLoader policyloader.PolicyLoader) (*RuleTable, error) {
	protoRT := NewProtoRuletable()

	if err := LoadPolicies(ctx, protoRT, policyLoader); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return NewRuleTable(protoRT)
}

func NewRuleTable(protoRT *runtimev1.RuleTable) (*RuleTable, error) {
	rt := &RuleTable{
		idx:          index.New(),
		programCache: NewProgramCache(),
	}

	if err := rt.init(protoRT); err != nil {
		return nil, err
	}

	return rt, nil
}

func (rt *RuleTable) init(protoRT *runtimev1.RuleTable) error {
	rt.RuleTable = protoRT

	if err := migrate(rt.RuleTable); err != nil {
		return err
	}

	// clear maps prior to creating new ones to reduce memory pressure in reload scenarios
	clear(rt.policyDerivedRoles)
	clear(rt.principalScopeMap)
	clear(rt.resourceScopeMap)
	clear(rt.scopeScopePermissions)
	rt.programCache.Clear()

	rt.idx.Reset()
	rt.policyDerivedRoles = make(map[namer.ModuleID]map[string]*WrappedRunnableDerivedRole)
	rt.principalScopeMap = make(map[string]struct{})
	rt.resourceScopeMap = make(map[string]struct{})
	rt.scopeScopePermissions = make(map[string]policyv1.ScopePermissions)

	if err := rt.indexRules(rt.Rules); err != nil {
		return err
	}

	// rules are now indexed, we can clear up any unnecessary transport state
	clear(rt.Rules)
	rt.Rules = []*runtimev1.RuleTable_RuleRow{} // otherwise the empty slice hangs around

	clear(rt.PolicyDerivedRoles)

	return nil
}

func (rt *RuleTable) indexRules(rules []*runtimev1.RuleTable_RuleRow) error {
	for _, rule := range rules {
		if rule.PolicyKind == policyv1.Kind_KIND_RESOURCE && !rule.FromRolePolicy {
			modID := namer.GenModuleIDFromFQN(rule.OriginFqn)
			if pdr, ok := rt.PolicyDerivedRoles[modID.RawValue()]; ok {
				if _, ok := rt.policyDerivedRoles[modID]; !ok {
					rt.policyDerivedRoles[modID] = make(map[string]*WrappedRunnableDerivedRole)
				}

				for n, dr := range pdr.DerivedRoles {
					rt.policyDerivedRoles[modID][n] = &WrappedRunnableDerivedRole{
						RunnableDerivedRole: dr,
						Constants:           (&structpb.Struct{Fields: dr.Constants}).AsMap(),
						VarCacheKey:         util.HashPB(dr, nil),
					}
				}
			}
		}

		if rule.ScopePermissions != policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
			rt.scopeScopePermissions[rule.Scope] = rule.ScopePermissions
		}

		switch rule.PolicyKind { //nolint:exhaustive
		case policyv1.Kind_KIND_PRINCIPAL:
			rt.principalScopeMap[rule.Scope] = struct{}{}
		case policyv1.Kind_KIND_RESOURCE:
			rt.resourceScopeMap[rule.Scope] = struct{}{}
		}
	}

	if err := rt.idx.IndexRules(rules); err != nil {
		return err
	}

	return rt.idx.IndexParentRoles(rt.ScopeParentRoles)
}

func (rt *RuleTable) GetAllRows() []*index.Binding {
	return rt.idx.GetAllRows()
}

func (rt *RuleTable) GetDerivedRoles(fqn string) map[string]*WrappedRunnableDerivedRole {
	return rt.policyDerivedRoles[namer.GenModuleIDFromFQN(fqn)]
}

func (rt *RuleTable) GetAllScopes(pt policyv1.Kind, scope, name, version string, lenient bool) ([]string, string, string) {
	var firstPolicyKey, firstFqn string
	var scopes []string

	var fqnFn func(string, string, string) string
	var scopeMap map[string]struct{}
	switch pt { //nolint:exhaustive
	case policyv1.Kind_KIND_PRINCIPAL:
		fqnFn = namer.PrincipalPolicyFQN
		scopeMap = rt.principalScopeMap
	case policyv1.Kind_KIND_RESOURCE:
		fqnFn = namer.ResourcePolicyFQN
		scopeMap = rt.resourceScopeMap
	}

	if _, ok := scopeMap[scope]; ok {
		firstFqn = fqnFn(name, version, scope)
		firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
		scopes = append(scopes, scope)
	} else if !lenient {
		return nil, "", ""
	}

	for s := range namer.ScopeParents(scope) {
		if _, ok := scopeMap[s]; ok {
			scopes = append(scopes, s)
			if firstPolicyKey == "" {
				firstFqn = fqnFn(name, version, s)
				firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
			}
		}
	}

	return scopes, firstPolicyKey, firstFqn
}

type scopeNode struct {
	children map[string]*scopeNode
	scope    string
}

func (rt *RuleTable) CombineScopes(principalScopes, resourceScopes []string) []string {
	// Build a map to track all unique scopes
	uniqueScopes := make(map[string]struct{})
	for _, s := range principalScopes {
		uniqueScopes[s] = struct{}{}
	}
	for _, s := range resourceScopes {
		uniqueScopes[s] = struct{}{}
	}

	root := &scopeNode{scope: "", children: make(map[string]*scopeNode)}

	for scope := range uniqueScopes {
		if scope == "" {
			continue
		}

		current := root
		parts := strings.Split(scope, ".")
		for i, part := range parts {
			fullPath := strings.Join(parts[:i+1], ".")
			if _, exists := current.children[part]; !exists {
				current.children[part] = &scopeNode{
					scope:    fullPath,
					children: make(map[string]*scopeNode),
				}
			}
			current = current.children[part]
		}
	}

	// Use DFS to traverse the tree with children first, then parents
	var result []string
	var dfs func(n *scopeNode)
	dfs = func(n *scopeNode) {
		childKeys := make([]string, 0, len(n.children))
		for k := range n.children {
			childKeys = append(childKeys, k)
		}

		for _, key := range childKeys {
			dfs(n.children[key])
		}

		if _, exists := uniqueScopes[n.scope]; exists {
			result = append(result, n.scope)
		}
	}
	dfs(root)

	return result
}

func (rt *RuleTable) GetScopeScopePermissions(scope string) policyv1.ScopePermissions {
	return rt.scopeScopePermissions[scope]
}

func (rt *RuleTable) GetSchema(fqn string) *policyv1.Schemas {
	modID := namer.GenModuleIDFromFQN(fqn)
	if s, ok := rt.Schemas[modID.RawValue()]; ok {
		return s
	}

	return nil
}

func (rt *RuleTable) GetMeta(fqn string) *runtimev1.RuleTableMetadata {
	modID := namer.GenModuleIDFromFQN(fqn)
	if s, ok := rt.Meta[modID.RawValue()]; ok {
		return s
	}

	return nil
}

func (rt *RuleTable) Evaluator(evalConf *evaluator.Conf, schemaConf *schema.Conf) (evaluator.Evaluator, error) {
	evaluator, err := NewEvaluator(evalConf, schemaConf, rt)
	return (*withoutAuditTrail)(evaluator), err
}

func migrate(rt *runtimev1.RuleTable) error {
	if rt.CompilerVersion == compilerVersion {
		return nil
	}

	log := logging.NewLogger("compiler")

	if rt.CompilerVersion > compilerVersion {
		log.Warnw(
			"Loading policies that were compiled by a newer version of Cerbos",
			"current_compiler_version", compilerVersion,
			"policies_compiler_version", rt.CompilerVersion,
		)
		return nil
	}

	log.Debugw(
		"Migrating compiled policies",
		logging.Uint32("from_compiler_version", rt.CompilerVersion),
		logging.Uint32("to_compiler_version", compilerVersion),
	)

	for version := rt.CompilerVersion; version < compilerVersion; version++ {
		err := compilerVersionMigrations[version](rt)
		if err != nil {
			return fmt.Errorf("failed to migrate compiled policies from v%d to v%d: %w", version, version+1, err)
		}
	}

	return nil
}

func migrateFromCompilerVersion0To1(rt *runtimev1.RuleTable) error {
	conditions.WalkExprs(rt, conditions.MigrateVariablesType)
	return nil
}
