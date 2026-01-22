// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/audit"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/ruletable/internal"
	"github.com/cerbos/cerbos/internal/ruletable/planner"
	"github.com/cerbos/cerbos/internal/schema"
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

	indexTimeout = time.Second * 10
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
				Condition:      rule.Condition,
				Scope:          p.Scope,
				Version:        p.Meta.Version,
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
	idx                   *index.Impl
	principalScopeMap     map[string]struct{}
	resourceScopeMap      map[string]struct{}
	scopeScopePermissions map[string]policyv1.ScopePermissions
	policyDerivedRoles    map[namer.ModuleID]map[string]*WrappedRunnableDerivedRole
	programCache          *ProgramCache
}

type WrappedRunnableDerivedRole struct {
	*runtimev1.RunnableDerivedRole
	Constants map[string]any
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

	return NewRuleTable(index.NewMem(), protoRT)
}

func NewRuleTable(idx index.Index, protoRT *runtimev1.RuleTable) (*RuleTable, error) {
	rt := &RuleTable{
		idx:          index.NewImpl(idx),
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

	rt.idx.PrecompileParentRoles(rt.ScopeParentRoles)

	// rules are now indexed, we can clear up any unnecessary transport state
	clear(rt.Rules)
	rt.Rules = []*runtimev1.RuleTable_RuleRow{} // otherwise the empty slice hangs around

	clear(rt.PolicyDerivedRoles)

	return nil
}

func (rt *RuleTable) indexRules(rules []*runtimev1.RuleTable_RuleRow) error {
	ctx, cancelFn := context.WithTimeout(context.Background(), indexTimeout)
	defer cancelFn()

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

	return rt.idx.IndexRules(ctx, rules)
}

func (rt *RuleTable) GetAllRows(ctx context.Context) ([]*index.Row, error) {
	return rt.idx.GetAllRows(ctx)
}

func (rt *RuleTable) GetDerivedRoles(fqn string) map[string]*WrappedRunnableDerivedRole {
	return rt.policyDerivedRoles[namer.GenModuleIDFromFQN(fqn)]
}

func (rt *RuleTable) GetAllScopes(pt policy.Kind, scope, name, version string) ([]string, string, string) {
	var firstPolicyKey, firstFqn string
	var scopes []string

	var fqnFn func(string, string, string) string
	switch pt { //nolint:exhaustive
	case policy.PrincipalKind:
		fqnFn = namer.PrincipalPolicyFQN
	case policy.ResourceKind:
		fqnFn = namer.ResourcePolicyFQN
	}

	if rt.ScopeExists(pt, scope) {
		firstFqn = fqnFn(name, version, scope)
		firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
		scopes = append(scopes, scope)
	}

	for s := range namer.ScopeParents(scope) {
		if rt.ScopeExists(pt, s) {
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

func (rt *RuleTable) ScopeExists(pt policy.Kind, scope string) bool {
	var ok bool
	switch pt { //nolint:exhaustive
	case policy.PrincipalKind:
		_, ok = rt.principalScopeMap[scope]
	case policy.ResourceKind:
		_, ok = rt.resourceScopeMap[scope]
	}

	return ok
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

func (rt *RuleTable) Check(ctx context.Context, conf *evaluator.Conf, schemaMgr schema.Manager, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	checkOpts := evaluator.NewCheckOptions(ctx, conf, opts...)
	tctx := tracing.StartTracer(checkOpts.TracerSink)

	// Primary use for this Evaluator interface is the ePDP, so we run the checks synchronously (for now)
	outputs := make([]*enginev1.CheckOutput, len(inputs))
	trail := &auditv1.AuditTrail{}
	for i, input := range inputs {
		out, t, err := rt.checkWithAuditTrail(ctx, tctx, schemaMgr, checkOpts.EvalParams, input)
		if err != nil {
			return nil, nil, err
		}

		outputs[i] = out
		trail = audit.MergeTrails(trail, t)
	}

	return outputs, trail, nil
}

func (rt *RuleTable) checkWithAuditTrail(ctx context.Context, tctx tracer.Context, schemaMgr schema.Manager, evalParams evaluator.EvalParams, input *enginev1.CheckInput) (*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	result, err := rt.check(ctx, tctx, schemaMgr, evalParams, input)
	if err != nil {
		return nil, nil, err
	}

	output := &enginev1.CheckOutput{
		RequestId:  input.RequestId,
		ResourceId: input.Resource.Id,
		Actions:    make(map[string]*enginev1.CheckOutput_ActionEffect, len(input.Actions)),
	}

	// update the output
	for _, action := range input.Actions {
		output.Actions[action] = &enginev1.CheckOutput_ActionEffect{
			Effect: effectv1.Effect_EFFECT_DENY,
			Policy: noPolicyMatch,
		}

		if einfo, ok := result.effects[action]; ok {
			ae := output.Actions[action]
			ae.Effect = einfo.Effect
			ae.Policy = einfo.Policy
			ae.Scope = einfo.Scope
		}
	}

	effectiveDerivedRoles := make([]string, 0, len(result.effectiveDerivedRoles))
	for edr := range result.effectiveDerivedRoles {
		effectiveDerivedRoles = append(effectiveDerivedRoles, edr)
	}
	output.EffectiveDerivedRoles = effectiveDerivedRoles
	output.ValidationErrors = result.validationErrors
	output.Outputs = result.outputs

	return output, result.auditTrail, nil
}

func (rt *RuleTable) check(ctx context.Context, tctx tracer.Context, schemaMgr schema.Manager, evalParams evaluator.EvalParams, input *enginev1.CheckInput) (*policyEvalResult, error) {
	_, span := tracing.StartSpan(ctx, "engine.Check")
	defer span.End()

	principalScope := evaluator.Scope(input.Principal.Scope, evalParams)
	principalVersion := input.Principal.PolicyVersion
	if principalVersion == "" {
		principalVersion = evalParams.DefaultPolicyVersion
	}

	resourceScope := evaluator.Scope(input.Resource.Scope, evalParams)
	resourceVersion := input.Resource.PolicyVersion
	if resourceVersion == "" {
		resourceVersion = evalParams.DefaultPolicyVersion
	}

	trail := newAuditTrail(make(map[string]*policyv1.SourceAttributes))
	result := newEvalResult(input.Actions, trail)

	if !evalParams.LenientScopeSearch &&
		!rt.ScopeExists(policy.PrincipalKind, principalScope) &&
		!rt.ScopeExists(policy.ResourceKind, resourceScope) {
		return result, nil
	}

	principalScopes, principalPolicyKey, _ := rt.GetAllScopes(policy.PrincipalKind, principalScope, input.Principal.Id, principalVersion)
	resourceScopes, resourcePolicyKey, fqn := rt.GetAllScopes(policy.ResourceKind, resourceScope, input.Resource.Kind, resourceVersion)

	span.SetAttributes(tracing.PolicyFQN(fqn))

	pctx := tctx.StartPolicy(fqn)

	// validate the input
	vr, err := schemaMgr.ValidateCheckInput(ctx, rt.GetSchema(fqn), input)
	if err != nil {
		pctx.Failed(err, "Error during validation")

		return nil, fmt.Errorf("failed to validate input: %w", err)
	}

	if len(vr.Errors) > 0 {
		result.validationErrors = vr.Errors.SchemaErrors()

		pctx.Failed(vr.Errors, "Validation errors")

		if vr.Reject {
			for _, action := range input.Actions {
				actx := pctx.StartAction(action)

				result.setEffect(action, EffectInfo{Effect: effectv1.Effect_EFFECT_DENY, Policy: resourcePolicyKey})

				actx.AppliedEffect(effectv1.Effect_EFFECT_DENY, "Rejected due to validation failures")
			}
			return result, nil
		}
	}

	request := checkInputToRequest(input)
	evalCtx := NewEvalContext(evalParams, request, rt.programCache)

	actionsToResolve := result.unresolvedActions()
	if len(actionsToResolve) == 0 {
		return result, nil
	}

	sanitizedResource := namer.SanitizedResource(input.Resource.Kind)
	scopedPrincipalExists, err := rt.idx.ScopedPrincipalExists(ctx, principalVersion, principalScopes)
	if err != nil {
		return nil, err
	}
	scopedResourceExists, err := rt.idx.ScopedResourceExists(ctx, resourceVersion, sanitizedResource, resourceScopes)
	if err != nil {
		return nil, err
	}

	if !scopedPrincipalExists && !scopedResourceExists {
		return result, nil
	}

	allRoles := rt.idx.AddParentRoles([]string{resourceScope}, input.Principal.Roles)
	includingParentRoles := make(map[string]struct{})
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	candidateRows, err := rt.idx.GetRows(ctx, []string{resourceVersion}, []string{sanitizedResource}, rt.CombineScopes(principalScopes, resourceScopes), allRoles, actionsToResolve, false)
	if err != nil {
		return nil, err
	}

	varCache := make(map[string]map[string]any)
	// We can cache evaluated conditions for combinations of parameters and conditions.
	// We use a compound key comprising the parameter origin and the rule FQN.
	conditionCache := make(map[string]bool)

	processedScopedDerivedRoles := make(map[string]struct{})
	policyTypes := []policyv1.Kind{policyv1.Kind_KIND_PRINCIPAL, policyv1.Kind_KIND_RESOURCE}
	for _, action := range actionsToResolve {
		actx := pctx.StartAction(action)

		var actionEffectInfo EffectInfo
		var mainPolicyKey string
		var scopes []string
		for _, pt := range policyTypes {
			if pt == policyv1.Kind_KIND_PRINCIPAL {
				mainPolicyKey = principalPolicyKey
				scopes = principalScopes
			} else {
				mainPolicyKey = resourcePolicyKey
				scopes = resourceScopes
			}

			// Reset `actionEffectInfo` for this policy type with the correct policy key.
			// This ensures we use the right policy name if no rules match
			actionEffectInfo.Effect = effectv1.Effect_EFFECT_NO_MATCH

			for i, role := range input.Principal.Roles {
				// Principal rules are role agnostic (they treat the rows as having a `*` role). Therefore we can
				// break out of the loop after the first iteration as it covers all potential principal rows.
				if i > 0 && pt == policyv1.Kind_KIND_PRINCIPAL {
					break
				}

				roleEffectSet := make(map[effectv1.Effect]struct{})
				roleEffectInfo := EffectInfo{
					Effect: effectv1.Effect_EFFECT_NO_MATCH,
					Policy: noPolicyMatch,
				}

				// a "policy" exists, regardless of potentially matching rules, so we update the policyKey
				if pt == policyv1.Kind_KIND_RESOURCE && scopedResourceExists ||
					pt == policyv1.Kind_KIND_PRINCIPAL && scopedPrincipalExists {
					roleEffectInfo.Policy = mainPolicyKey
				}

				parentRoles := rt.idx.AddParentRoles([]string{resourceScope}, []string{role})

			scopesLoop:
				for _, scope := range scopes {
					sctx := actx.StartScope(scope)

					// This is for backwards compatibility with effectiveDerivedRoles.
					// If we reach this point, we can assert that the given {origin policy + scope} combination has been evaluated
					// and therefore we build the effectiveDerivedRoles from those referenced in the policy.
					if pt == policyv1.Kind_KIND_RESOURCE { //nolint:nestif
						if _, ok := processedScopedDerivedRoles[scope]; !ok { //nolint:nestif
							effectiveDerivedRoles := make(internal.StringSet)
							if drs := rt.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, scope)); drs != nil {
								for name, dr := range drs {
									drctx := tctx.StartPolicy(dr.OriginFqn).StartDerivedRole(name)
									if !internal.SetIntersects(dr.ParentRoles, includingParentRoles) {
										drctx.Skipped(nil, "No matching roles")
										continue
									}

									var variables map[string]any
									key := namer.DerivedRolesFQN(name)
									if c, ok := varCache[key]; ok {
										variables = c
									} else {
										var err error
										variables, err = evalCtx.evaluateVariables(ctx, drctx.StartVariables(), dr.Constants, dr.OrderedVariables)
										if err != nil {
											return nil, err
										}
										varCache[key] = variables
									}

									// we don't use `conditionCache` as we don't do any evaluations scoped solely to derived role conditions
									ok, err := evalCtx.SatisfiesCondition(ctx, drctx.StartCondition(), dr.Condition, dr.Constants, variables)
									if err != nil {
										continue
									}

									if ok {
										effectiveDerivedRoles[name] = struct{}{}
										result.effectiveDerivedRoles[name] = struct{}{}
									}
								}
							}

							evalCtx = evalCtx.withEffectiveDerivedRoles(effectiveDerivedRoles)

							processedScopedDerivedRoles[scope] = struct{}{}
						}
					}

					if roleEffectInfo.Effect != effectv1.Effect_EFFECT_NO_MATCH {
						break
					}

					// Only process rows that match the current policy type
					for _, row := range candidateRows {
						if !row.Matches(pt, scope, action, input.Principal.Id, parentRoles) {
							continue
						}

						rulectx := sctx.StartRule(row.Name)

						if m := rt.GetMeta(row.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
							maps.Copy(result.auditTrail.EffectivePolicies, m.GetSourceAttributes())
						}

						var constants map[string]any
						var variables map[string]any
						if row.Params != nil {
							constants = row.Params.Constants
							if c, ok := varCache[row.Params.Key]; ok {
								variables = c
							} else {
								var err error
								variables, err = evalCtx.evaluatePrograms(pctx.StartVariables(), constants, row.Params.CelPrograms)
								if err != nil {
									pctx.Skipped(err, "Error evaluating variables")
									return nil, err
								}
								varCache[row.Params.Key] = variables
							}
						}

						var satisfiesCondition bool
						if c, ok := conditionCache[row.EvaluationKey]; ok { //nolint:nestif
							satisfiesCondition = c
						} else {
							// We evaluate the derived role condition (if any) first, as this leads to a more sane engine trace output.
							if row.DerivedRoleCondition != nil {
								drctx := rulectx.StartDerivedRole(row.OriginDerivedRole)
								var derivedRoleConstants map[string]any
								var derivedRoleVariables map[string]any
								if row.DerivedRoleParams != nil {
									derivedRoleConstants = row.DerivedRoleParams.Constants
									if c, ok := varCache[row.DerivedRoleParams.Key]; ok {
										derivedRoleVariables = c
									} else {
										var err error
										derivedRoleVariables, err = evalCtx.evaluatePrograms(drctx.StartVariables(), derivedRoleConstants, row.DerivedRoleParams.CelPrograms)
										if err != nil {
											drctx.Skipped(err, "Error evaluating derived role variables")
											return nil, err
										}
										varCache[row.DerivedRoleParams.Key] = derivedRoleVariables
									}
								}

								// Derived role engine trace logs are handled above. Because derived role conditions are baked into the rule table rows, we don't want to
								// confuse matters by adding condition trace logs if a rule is referencing a derived role, so we pass a no-op context here.
								// TODO(saml) we could probably pre-compile the condition also
								drSatisfied, err := evalCtx.SatisfiesCondition(ctx, tracing.StartTracer(nil), row.DerivedRoleCondition, derivedRoleConstants, derivedRoleVariables)
								if err != nil {
									rulectx.Skipped(err, "Error evaluating derived role condition")
									continue
								}

								// terminate early if the derived role condition isn't satisfied, which is consistent with the pre-rule table implementation
								if !drSatisfied {
									rulectx.Skipped(err, "No matching derived roles")
									conditionCache[row.EvaluationKey] = false
									continue
								}
							}

							isSatisfied, err := evalCtx.SatisfiesCondition(ctx, rulectx.StartCondition(), row.Condition, constants, variables)
							if err != nil {
								rulectx.Skipped(err, "Error evaluating condition")
								continue
							}

							conditionCache[row.EvaluationKey] = isSatisfied
							satisfiesCondition = isSatisfied
						}

						if satisfiesCondition { //nolint:nestif
							var outputExpr *exprpb.CheckedExpr
							if row.EmitOutput != nil && row.EmitOutput.When != nil && row.EmitOutput.When.RuleActivated != nil {
								outputExpr = row.EmitOutput.When.RuleActivated.Checked
							}

							if outputExpr != nil {
								octx := rulectx.StartOutput(row.Name)
								output := &enginev1.OutputEntry{
									Src:    namer.RuleFQN(rt.GetMeta(row.OriginFqn), row.Scope, row.Name),
									Val:    evalCtx.evaluateProtobufValueCELExpr(ctx, outputExpr, row.Params.Constants, variables),
									Action: action,
								}
								result.outputs = append(result.outputs, output)
								octx.ComputedOutput(output)
							}

							roleEffectSet[row.Effect] = struct{}{}
							if row.Effect == effectv1.Effect_EFFECT_DENY {
								roleEffectInfo.Effect = effectv1.Effect_EFFECT_DENY
								roleEffectInfo.Scope = scope
								if row.FromRolePolicy {
									// Implicit DENY generated as a result of no matching role policy action
									// needs to be attributed to said role policy
									roleEffectInfo.Policy = namer.PolicyKeyFromFQN(row.OriginFqn)
								}
								break scopesLoop
							} else if row.NoMatchForScopePermissions {
								roleEffectInfo.Policy = noMatchScopePermissions
								roleEffectInfo.Scope = scope
							}
						} else {
							if row.EmitOutput != nil && row.EmitOutput.When != nil && row.EmitOutput.When.ConditionNotMet != nil {
								octx := rulectx.StartOutput(row.Name)
								output := &enginev1.OutputEntry{
									Src:    namer.RuleFQN(rt.GetMeta(row.OriginFqn), row.Scope, row.Name),
									Val:    evalCtx.evaluateProtobufValueCELExpr(ctx, row.EmitOutput.When.ConditionNotMet.Checked, row.Params.Constants, variables),
									Action: action,
								}
								result.outputs = append(result.outputs, output)
								octx.ComputedOutput(output)
							}
							rulectx.Skipped(nil, conditionNotSatisfied)
						}
					}

					if _, hasAllow := roleEffectSet[effectv1.Effect_EFFECT_ALLOW]; hasAllow {
						switch rt.GetScopeScopePermissions(scope) { //nolint:exhaustive
						case policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS:
							delete(roleEffectSet, effectv1.Effect_EFFECT_ALLOW)
						case policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT:
							roleEffectInfo.Effect = effectv1.Effect_EFFECT_ALLOW
							roleEffectInfo.Scope = scope
							break scopesLoop
						}
					}
				}

				// Match the first result
				if actionEffectInfo.Effect == effectv1.Effect_EFFECT_NO_MATCH {
					actionEffectInfo = roleEffectInfo
				}

				if roleEffectInfo.Effect == effectv1.Effect_EFFECT_ALLOW {
					// Finalise and return the first independent ALLOW
					actionEffectInfo = roleEffectInfo
					break
				} else if roleEffectInfo.Effect == effectv1.Effect_EFFECT_DENY &&
					actionEffectInfo.Policy == noMatchScopePermissions &&
					roleEffectInfo.Policy != noMatchScopePermissions {
					// Override `noMatchScopePermissions` DENYs with explicit ones for clarity
					actionEffectInfo = roleEffectInfo
				}
			}

			// Skip to next action if this action already has a definitive result from principal policies
			if actionEffectInfo.Effect == effectv1.Effect_EFFECT_ALLOW || actionEffectInfo.Effect == effectv1.Effect_EFFECT_DENY {
				break
			}
		}

		if actionEffectInfo.Effect == effectv1.Effect_EFFECT_NO_MATCH {
			actionEffectInfo.Effect = effectv1.Effect_EFFECT_DENY
		}

		result.setEffect(action, actionEffectInfo)
		actx.AppliedEffect(actionEffectInfo.Effect, "")
	}

	return result, nil
}

type EffectInfo struct {
	Policy string
	Scope  string
	Effect effectv1.Effect
}

type policyEvalResult struct {
	effects               map[string]EffectInfo
	effectiveDerivedRoles map[string]struct{}
	toResolve             map[string]struct{}
	auditTrail            *auditv1.AuditTrail
	validationErrors      []*schemav1.ValidationError
	outputs               []*enginev1.OutputEntry
}

func newEvalResult(actions []string, auditTrail *auditv1.AuditTrail) *policyEvalResult {
	per := &policyEvalResult{
		effects:               make(map[string]EffectInfo, len(actions)),
		effectiveDerivedRoles: make(map[string]struct{}),
		toResolve:             make(map[string]struct{}, len(actions)),
		outputs:               []*enginev1.OutputEntry{},
		auditTrail:            auditTrail,
	}

	for _, a := range actions {
		per.toResolve[a] = struct{}{}
	}

	return per
}

func (er *policyEvalResult) unresolvedActions() []string {
	if len(er.toResolve) == 0 {
		return nil
	}

	res := make([]string, len(er.toResolve))
	i := 0
	for ua := range er.toResolve {
		res[i] = ua
		i++
	}

	return res
}

// setEffect sets the effect for an action. DENY always takes precedence.
func (er *policyEvalResult) setEffect(action string, effect EffectInfo) {
	delete(er.toResolve, action)

	if effect.Effect == effectv1.Effect_EFFECT_DENY {
		er.effects[action] = effect
		return
	}

	current, ok := er.effects[action]
	if !ok {
		er.effects[action] = effect
		return
	}

	if current.Effect != effectv1.Effect_EFFECT_DENY {
		er.effects[action] = effect
	}
}

func newAuditTrail(srcAttr map[string]*policyv1.SourceAttributes) *auditv1.AuditTrail {
	return &auditv1.AuditTrail{EffectivePolicies: maps.Clone(srcAttr)}
}

func checkInputToRequest(input *enginev1.CheckInput) *enginev1.Request {
	return &enginev1.Request{
		Principal: &enginev1.Request_Principal{
			Id:            input.Principal.Id,
			Roles:         input.Principal.Roles,
			Attr:          input.Principal.Attr,
			PolicyVersion: input.Principal.PolicyVersion,
			Scope:         namer.ScopeValue(input.Principal.Scope),
		},
		Resource: &enginev1.Request_Resource{
			Kind:          input.Resource.Kind,
			Id:            input.Resource.Id,
			Attr:          input.Resource.Attr,
			PolicyVersion: input.Resource.PolicyVersion,
			Scope:         namer.ScopeValue(input.Resource.Scope),
		},
		AuxData: input.AuxData,
	}
}

type EvalContext struct {
	request               *enginev1.Request
	runtime               *enginev1.Runtime
	effectiveDerivedRoles internal.StringSet
	programCache          *ProgramCache
	evaluator.EvalParams
}

func NewEvalContext(ep evaluator.EvalParams, request *enginev1.Request, programCache *ProgramCache) *EvalContext {
	return &EvalContext{
		EvalParams:   ep,
		request:      request,
		programCache: programCache,
	}
}

func (ec *EvalContext) withEffectiveDerivedRoles(effectiveDerivedRoles internal.StringSet) *EvalContext {
	return &EvalContext{
		EvalParams:            ec.EvalParams,
		request:               ec.request,
		effectiveDerivedRoles: effectiveDerivedRoles,
		programCache:          ec.programCache,
	}
}

func (ec *EvalContext) lazyRuntime() any { // We have to return `any` rather than `*enginev1.Runtime` here to be able to use this function as a lazy binding in the CEL evaluator.
	if ec.runtime == nil {
		ec.runtime = &enginev1.Runtime{}
		if len(ec.effectiveDerivedRoles) > 0 {
			ec.runtime.EffectiveDerivedRoles = ec.effectiveDerivedRoles.Values()
			sort.Strings(ec.runtime.EffectiveDerivedRoles)
		}
	}

	return ec.runtime
}

func (ec *EvalContext) evaluateVariables(ctx context.Context, tctx tracer.Context, constants map[string]any, variables []*runtimev1.Variable) (map[string]any, error) {
	var errs error
	evalVars := make(map[string]any, len(variables))
	for _, variable := range variables {
		vctx := tctx.StartVariable(variable.Name, variable.Expr.Original)
		val, err := ec.evaluateCELExprToRaw(ctx, variable.Expr.Checked, constants, evalVars)
		if err != nil {
			vctx.Skipped(err, "Failed to evaluate expression")
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s := %s`: %w", variable.Name, variable.Expr.Original, err))
			continue
		}

		evalVars[variable.Name] = val
		vctx.ComputedResult(val)
	}

	return evalVars, errs
}

func (ec *EvalContext) buildEvalVars(constants, variables map[string]any) map[string]any {
	return map[string]any{
		conditions.CELRequestIdent:       ec.request,
		conditions.CELResourceAbbrev:     ec.request.Resource,
		conditions.CELPrincipalAbbrev:    ec.request.Principal,
		conditions.CELRuntimeIdent:       ec.lazyRuntime,
		conditions.CELConstantsIdent:     constants,
		conditions.CELConstantsAbbrev:    constants,
		conditions.CELVariablesIdent:     variables,
		conditions.CELVariablesAbbrev:    variables,
		conditions.CELGlobalsIdent:       ec.Globals,
		conditions.CELGlobalsAbbrev:      ec.Globals,
		conditions.CELNowFnActivationKey: ec.NowFunc,
	}
}

func (ec *EvalContext) evaluatePrograms(tctx tracer.Context, constants map[string]any, celPrograms []*index.CelProgram) (map[string]any, error) {
	var errs error

	evalVars := make(map[string]any, len(celPrograms))
	for _, prg := range celPrograms {
		vctx := tctx.StartVariable(prg.Name, prg.Expr)
		result, _, err := prg.Prog.Eval(ec.buildEvalVars(constants, evalVars))
		if err != nil {
			// Ignore errors for expressions that evaluate to an error value (e.g., missing keys).
			// This matches the behavior of evaluateCELExpr which returns nil for such cases.
			if types.IsError(result) {
				vctx.ComputedResult(nil)
				continue
			}
			vctx.Skipped(err, "Failed to evaluate expression")
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s`: %w", prg.Name, err))
			continue
		}

		val := result.Value()
		evalVars[prg.Name] = val
		vctx.ComputedResult(val)
	}

	return evalVars, errs
}

func (ec *EvalContext) SatisfiesCondition(ctx context.Context, tctx tracer.Context, cond *runtimev1.Condition, constants, variables map[string]any) (bool, error) {
	if cond == nil {
		tctx.ComputedBoolResult(true, nil, "")
		return true, nil
	}

	switch t := cond.Op.(type) {
	case *runtimev1.Condition_Expr:
		ectx := tctx.StartExpr(t.Expr.Original)
		val, err := ec.evaluateBoolCELExpr(ctx, t.Expr.Checked, constants, variables)
		if err != nil {
			ectx.ComputedBoolResult(false, err, "Failed to evaluate expression")
			return false, fmt.Errorf("failed to evaluate `%s`: %w", t.Expr.Original, err)
		}

		ectx.ComputedBoolResult(val, nil, "")
		return val, nil

	case *runtimev1.Condition_All:
		actx := tctx.StartConditionAll()
		for i, expr := range t.All.Expr {
			val, err := ec.SatisfiesCondition(ctx, actx.StartNthCondition(i), expr, constants, variables)
			if err != nil {
				actx.ComputedBoolResult(false, err, "Short-circuited")
				return false, err
			}

			if !val {
				actx.ComputedBoolResult(false, nil, "Short-circuited")
				return false, nil
			}
		}

		actx.ComputedBoolResult(true, nil, "")
		return true, nil

	case *runtimev1.Condition_Any:
		actx := tctx.StartConditionAny()
		for i, expr := range t.Any.Expr {
			val, err := ec.SatisfiesCondition(ctx, actx.StartNthCondition(i), expr, constants, variables)
			if err != nil {
				actx.ComputedBoolResult(false, err, "Short-circuited")
				return false, err
			}

			if val {
				actx.ComputedBoolResult(true, nil, "Short-circuited")
				return true, nil
			}
		}

		actx.ComputedBoolResult(false, nil, "")
		return false, nil

	case *runtimev1.Condition_None:
		actx := tctx.StartConditionNone()
		for i, expr := range t.None.Expr {
			val, err := ec.SatisfiesCondition(ctx, actx.StartNthCondition(i), expr, constants, variables)
			if err != nil {
				actx.ComputedBoolResult(false, err, "Short-circuited")
				return false, err
			}

			if val {
				actx.ComputedBoolResult(false, nil, "Short-circuited")
				return false, nil
			}
		}

		actx.ComputedBoolResult(true, nil, "")
		return true, nil

	default:
		err := fmt.Errorf("unknown op type %T", t)
		tctx.ComputedBoolResult(false, err, "Unknown op type")
		return false, err
	}
}

func (ec *EvalContext) evaluateBoolCELExpr(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) (bool, error) {
	val, err := ec.evaluateCELExprToRaw(ctx, expr, constants, variables)
	if err != nil {
		return false, err
	}

	if val == nil {
		return false, nil
	}

	boolVal, ok := val.(bool)
	if !ok {
		return false, nil
	}

	return boolVal, nil
}

func (ec *EvalContext) evaluateProtobufValueCELExpr(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) *structpb.Value {
	result, err := ec.evaluateCELExpr(ctx, expr, constants, variables)
	if err != nil {
		return structpb.NewStringValue("<failed to evaluate expression>")
	}

	if result == nil {
		return nil
	}

	val, err := result.ConvertToNative(reflect.TypeFor[*structpb.Value]())
	if err != nil {
		return structpb.NewStringValue("<failed to convert evaluation to protobuf value>")
	}

	pbVal, ok := val.(*structpb.Value)
	if !ok {
		// Something is broken in `ConvertToNative`
		return structpb.NewStringValue("<failed to convert evaluation to protobuf value>")
	}

	return pbVal
}

func (ec *EvalContext) evaluateCELExpr(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) (ref.Val, error) {
	if expr == nil {
		return nil, nil
	}

	prg, err := ec.programCache.GetOrCreate(expr)
	if err != nil {
		return nil, err
	}

	result, _, err := prg.ContextEval(ctx, ec.buildEvalVars(constants, variables))
	if err != nil {
		// ignore expressions that are invalid
		if types.IsError(result) {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (ec *EvalContext) evaluateCELExprToRaw(ctx context.Context, expr *exprpb.CheckedExpr, constants, variables map[string]any) (any, error) {
	result, err := ec.evaluateCELExpr(ctx, expr, constants, variables)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, nil
	}

	return result.Value(), nil
}

func (rt *RuleTable) Plan(ctx context.Context, conf *evaluator.Conf, schemaMgr schema.Manager, input *enginev1.PlanResourcesInput, opts ...evaluator.CheckOpt) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	checkOpts := evaluator.NewCheckOptions(ctx, conf, opts...)

	principalScope := evaluator.Scope(input.Principal.Scope, checkOpts.EvalParams)
	principalVersion := evaluator.PolicyVersion(input.Principal.PolicyVersion, checkOpts.EvalParams)

	resourceScope := evaluator.Scope(input.Resource.Scope, checkOpts.EvalParams)
	resourceVersion := evaluator.PolicyVersion(input.Resource.PolicyVersion, checkOpts.EvalParams)

	return rt.planWithAuditTrail(ctx, schemaMgr, input, principalScope, principalVersion, resourceScope, resourceVersion, checkOpts.NowFunc(), checkOpts.Globals())
}

func (rt *RuleTable) planWithAuditTrail(
	ctx context.Context,
	schemaMgr schema.Manager,
	input *enginev1.PlanResourcesInput,
	principalScope, principalVersion, resourceScope, resourceVersion string,
	nowFunc conditions.NowFunc, globals map[string]any,
) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	fqn := namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, resourceScope)

	_, span := tracing.StartSpan(ctx, "engine.Plan")
	span.SetAttributes(tracing.PolicyFQN(fqn))
	defer span.End()

	principalScopes, _, _ := rt.GetAllScopes(policy.PrincipalKind, principalScope, input.Principal.Id, principalVersion)
	resourceScopes, _, _ := rt.GetAllScopes(policy.ResourceKind, resourceScope, input.Resource.Kind, resourceVersion)

	request := planner.PlanResourcesInputToRequest(input)
	evalCtx := &planner.EvalContext{TimeFn: nowFunc}

	effectivePolicies := make(map[string]*policyv1.SourceAttributes)
	auditTrail := &auditv1.AuditTrail{EffectivePolicies: effectivePolicies}

	filters := make([]*enginev1.PlanResourcesFilter, 0, len(input.Actions))
	matchedScopes := make(map[string]string, len(input.Actions))
	vr, err := schemaMgr.ValidatePlanResourcesInput(ctx, rt.GetSchema(fqn), input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate input: %w", err)
	}
	var validationErrors []*schemav1.ValidationError
	if len(vr.Errors) > 0 {
		validationErrors = vr.Errors.SchemaErrors()

		if vr.Reject {
			output := planner.MkPlanResourcesOutput(input, nil, validationErrors)
			output.Filter = &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED}
			output.FilterDebug = planner.FilterToString(output.Filter)
			return output, auditTrail, nil
		}
	}

	allRoles := rt.idx.AddParentRoles([]string{resourceScope}, input.Principal.Roles)
	scopes := rt.CombineScopes(principalScopes, resourceScopes)
	candidateRows, err := rt.idx.GetRows(ctx, []string{resourceVersion}, []string{namer.SanitizedResource(input.Resource.Kind)}, scopes, allRoles, input.Actions, false)
	if err != nil {
		return nil, nil, err
	}
	if len(candidateRows) == 0 {
		output := planner.MkPlanResourcesOutput(input, nil, validationErrors)
		output.Filter = &enginev1.PlanResourcesFilter{Kind: enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED}
		output.FilterDebug = noPolicyMatch
		return output, auditTrail, nil
	}

	includingParentRoles := make(map[string]struct{})
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	policyMatch := false
	for _, action := range input.Actions {
		matchedScopes[action] = ""
		nf := new(planner.NodeFilter)
		scopedDerivedRolesList := make(map[string]func() (*exprpb.Expr, error))

		var hasPolicyTypeAllow bool
		var rootNode *planner.QpN

		// evaluate resource policies before principal policies
		for _, pt := range []policyv1.Kind{policyv1.Kind_KIND_RESOURCE, policyv1.Kind_KIND_PRINCIPAL} {
			var policyTypeAllowNode, policyTypeDenyNode *planner.QpN

			for i, role := range input.Principal.Roles {
				// Principal rules are role agnostic (they treat the rows as having a `*` role). Therefore we can
				// break out of the loop after the first iteration as it covers all potential principal rows.
				if i > 0 && pt == policyv1.Kind_KIND_PRINCIPAL {
					break
				}

				var roleAllowNode *planner.QpN
				var roleDenyNode *planner.QpN
				var roleDenyRolePolicyNode *planner.QpN
				var pendingAllow bool

				rolesIncludingParents := rt.idx.AddParentRoles([]string{resourceScope}, []string{role})

				for _, scope := range scopes {
					var scopeAllowNode *planner.QpN
					var scopeDenyNode *planner.QpN
					var scopeDenyRolePolicyNode *planner.QpN

					derivedRolesList := planner.MkDerivedRolesList(nil)
					if pt == policyv1.Kind_KIND_RESOURCE { //nolint:nestif
						if c, ok := scopedDerivedRolesList[scope]; ok {
							derivedRolesList = c
						} else {
							var derivedRoles []planner.RN
							if drs := rt.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, scope)); drs != nil {
								for name, dr := range drs {
									if !internal.SetIntersects(dr.ParentRoles, includingParentRoles) {
										continue
									}

									var err error
									variables, err := planner.VariableExprs(dr.OrderedVariables)
									if err != nil {
										return nil, auditTrail, err
									}

									node, err := evalCtx.EvaluateCondition(ctx, dr.Condition, request, globals, dr.Constants, variables, derivedRolesList)
									if err != nil {
										return nil, auditTrail, err
									}

									derivedRoles = append(derivedRoles, planner.RN{
										Node: func() (*enginev1.PlanResourcesAst_Node, error) {
											return node, nil
										},
										Role: name,
									})
								}
							}

							sort.Slice(derivedRoles, func(i, j int) bool {
								return derivedRoles[i].Role < derivedRoles[j].Role
							})

							derivedRolesList = planner.MkDerivedRolesList(derivedRoles)

							scopedDerivedRolesList[scope] = derivedRolesList
						}
					}

					for _, row := range candidateRows {
						if ok := row.Matches(pt, scope, action, input.Principal.Id, rolesIncludingParents); !ok {
							continue
						}

						if m := rt.GetMeta(row.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
							maps.Copy(effectivePolicies, m.GetSourceAttributes())
						}

						var constants map[string]any
						var variables map[string]celast.Expr
						if row.Params != nil {
							constants = row.Params.Constants
							var err error
							variables, err = planner.VariableExprs(row.Params.Variables)
							if err != nil {
								return nil, auditTrail, err
							}
						}

						node, err := evalCtx.EvaluateCondition(ctx, row.Condition, request, globals, constants, variables, derivedRolesList)
						if err != nil {
							return nil, auditTrail, err
						}

						if row.DerivedRoleCondition != nil { //nolint:nestif
							var variables map[string]celast.Expr
							if row.DerivedRoleParams != nil {
								var err error
								variables, err = planner.VariableExprs(row.DerivedRoleParams.Variables)
								if err != nil {
									return nil, auditTrail, err
								}
							}

							drNode, err := evalCtx.EvaluateCondition(ctx, row.DerivedRoleCondition, request, globals, row.DerivedRoleParams.Constants, variables, derivedRolesList)
							if err != nil {
								return nil, auditTrail, err
							}

							if row.Condition == nil {
								node = drNode
							} else {
								node = planner.MkNodeFromLO(planner.MkAndLogicalOperation([]*planner.QpN{node, drNode}))
							}
						}

						switch row.Effect { //nolint:exhaustive
						case effectv1.Effect_EFFECT_ALLOW:
							scopeAllowNode = addNode(scopeAllowNode, node, planner.MkOrNode)
						case effectv1.Effect_EFFECT_DENY:
							// ignore constant false DENY nodes
							if b, ok := planner.IsNodeConstBool(node); ok && !b {
								continue
							}

							if row.FromRolePolicy {
								scopeDenyRolePolicyNode = addNode(scopeDenyRolePolicyNode, node, planner.MkOrNode)
							} else {
								scopeDenyNode = addNode(scopeDenyNode, node, planner.MkOrNode)
							}
						}
					}

					roleDenyNode = addNode(roleDenyNode, scopeDenyNode, planner.MkOrNode)
					roleDenyRolePolicyNode = addNode(roleDenyRolePolicyNode, scopeDenyRolePolicyNode, planner.MkOrNode)

					if scopeAllowNode != nil { //nolint:nestif
						if roleAllowNode == nil {
							roleAllowNode = scopeAllowNode
						} else {
							if pendingAllow {
								roleAllowNode = planner.MkAndNode([]*planner.QpN{roleAllowNode, scopeAllowNode})
								pendingAllow = false
							} else {
								roleAllowNode = planner.MkOrNode([]*planner.QpN{roleAllowNode, scopeAllowNode})
							}
						}

						if rt.GetScopeScopePermissions(scope) == policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS {
							pendingAllow = true
						}
					}

					if (scopeDenyNode != nil || scopeDenyRolePolicyNode != nil || scopeAllowNode != nil) &&
						rt.GetScopeScopePermissions(scope) == policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT {
						matchedScopes[action] = scope
					}
				}

				// only an ALLOW from a scope with ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS exists with no
				// matching rules in the parent scopes, therefore null the node
				if pendingAllow {
					roleAllowNode = nil
				}

				// Const DENY overrides any ALLOW in the same role. Check both deny types.
				constTrue := false
				if b, ok := planner.IsNodeConstBool(roleDenyNode); ok && b {
					constTrue = true
				} else if b, ok := planner.IsNodeConstBool(roleDenyRolePolicyNode); ok && b {
					constTrue = true
				}

				if constTrue {
					// Roles are evaluated independently, therefore an ALLOW for one role needs to override a DENY for another.
					// If we pass the role level `DENY==true`, we end up overriding the result for all roles with an `AND(..., NOT(true))`
					// due to the policyTypeDenyNode inversion below. Inverting and resolving in the allow node ensures the role is OR'd
					// against others, e.g. `OR(false, roleAllow1, roleAllow2, ...)`).
					roleAllowNode = planner.MkFalseNode()
					roleDenyNode = nil
					roleDenyRolePolicyNode = nil
				} else if roleAllowNode != nil && roleDenyNode == nil && roleDenyRolePolicyNode == nil {
					if b, ok := planner.IsNodeConstBool(roleAllowNode); ok && b {
						policyTypeAllowNode = roleAllowNode
						policyTypeDenyNode = nil
						// Break out of the roles loop entirely
						break
					}
				}

				// If there is a role policy restriction for this specific role, we must apply it here.
				// An ALLOW from this role is valid ONLY IF it is NOT denied by this role's role policy.
				if roleDenyRolePolicyNode != nil && roleAllowNode != nil {
					roleAllowNode = planner.MkAndNode([]*planner.QpN{
						roleAllowNode,
						planner.InvertNodeBooleanValue(roleDenyRolePolicyNode),
					})
				}

				policyTypeAllowNode = addNode(policyTypeAllowNode, roleAllowNode, planner.MkOrNode)
				policyTypeDenyNode = addNode(policyTypeDenyNode, roleDenyNode, planner.MkOrNode)
			}

			if policyTypeAllowNode != nil {
				hasPolicyTypeAllow = true
			}

			if policyTypeAllowNode != nil {
				if rootNode == nil {
					rootNode = policyTypeAllowNode
				} else {
					rootNode = planner.MkOrNode([]*planner.QpN{policyTypeAllowNode, rootNode})
				}
			}

			// PolicyType denies need to reside at the top level of their PolicyType sub trees (e.g. a conditional
			// DENY in a principal policy needs to be a top level `(NOT deny condition) AND nested ALLOW`), so we
			// invert and AND them as we go.
			if policyTypeDenyNode != nil {
				inv := planner.InvertNodeBooleanValue(policyTypeDenyNode)
				if rootNode == nil {
					rootNode = inv
				} else {
					rootNode = planner.MkAndNode([]*planner.QpN{inv, rootNode})
				}
			}
		}

		if rootNode != nil {
			policyMatch = true
			if !hasPolicyTypeAllow {
				nf.ResetToUnconditionalDeny()
			} else {
				nf.Add(rootNode, effectv1.Effect_EFFECT_ALLOW)
			}
		}

		if nf.AllowIsEmpty() && !nf.DenyIsEmpty() { // reset a conditional DENY to an unconditional one
			nf.ResetToUnconditionalDeny()
		}
		f, err := planner.ToFilter(nf.ToAST())
		if err != nil {
			return nil, nil, err
		}
		filters = append(filters, f)
	} // for each action
	output := planner.MkPlanResourcesOutput(input, matchedScopes, validationErrors)
	output.Filter, output.FilterDebug, err = planner.MergeWithAnd(filters)
	if err != nil {
		return nil, nil, err
	}
	if !policyMatch {
		output.FilterDebug = noPolicyMatch
	}

	return output, auditTrail, nil
}

func addNode(curr, next *planner.QpN, combine func([]*planner.QpN) *planner.QpN) *planner.QpN {
	if next == nil {
		return curr
	}
	if curr == nil {
		return next
	}
	return combine([]*planner.QpN{curr, next})
}

func (rt *RuleTable) Evaluator(evalConf *evaluator.Conf, schemaConf *schema.Conf) (evaluator.Evaluator, error) {
	evaluator, err := NewEvaluator(evalConf, schemaConf, rt)
	return (*withoutAuditTrail)(evaluator), err
}

// ListRuleTableRowActions returns unique list of actions in a rule table row.
func ListRuleTableRowActions(row *index.Row) []string {
	var actions []string
	if row == nil {
		return actions
	}

	ss := make(util.StringSet)

	switch a := row.GetActionSet().(type) {
	case *runtimev1.RuleTable_RuleRow_Action:
		if !ss.Contains(a.Action) {
			actions = append(actions, a.Action)
		}

	case *runtimev1.RuleTable_RuleRow_AllowActions_:
		for action := range a.AllowActions.Actions {
			if !ss.Contains(action) {
				actions = append(actions, action)
			}
		}
	}

	if len(actions) > 1 {
		slices.Sort(actions)
	}

	return actions
}

// ListRuleTableRowConstants returns local and exported constants defined in a rule table row.
func ListRuleTableRowConstants(row *index.Row) []*responsev1.InspectPoliciesResponse_Constant {
	if row == nil {
		return nil
	}

	constants := make([]*responsev1.InspectPoliciesResponse_Constant, len(row.GetParams().GetConstants())+len(row.GetDerivedRoleParams().GetConstants()))
	i := 0
	for name, value := range row.GetParams().GetConstants() {
		constants[i] = &responsev1.InspectPoliciesResponse_Constant{
			Name:  name,
			Value: value,
			Kind:  responsev1.InspectPoliciesResponse_Constant_KIND_UNKNOWN,
		}

		i++
	}

	for name, value := range row.GetDerivedRoleParams().GetConstants() {
		constants[i] = &responsev1.InspectPoliciesResponse_Constant{
			Name:  name,
			Value: value,
			Kind:  responsev1.InspectPoliciesResponse_Constant_KIND_UNKNOWN,
		}

		i++
	}

	if len(constants) > 1 {
		slices.SortFunc(constants, func(a, b *responsev1.InspectPoliciesResponse_Constant) int {
			if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
				return kind
			}

			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return constants
}

// GetRuleTableRowDerivedRoles returns the derived role defined in a rule table row if it exists.
func GetRuleTableRowDerivedRoles(row *index.Row) *responsev1.InspectPoliciesResponse_DerivedRole {
	if row == nil || row.GetOriginDerivedRole() == "" {
		return nil
	}

	return &responsev1.InspectPoliciesResponse_DerivedRole{
		Name: row.GetOriginDerivedRole(),
		Kind: responsev1.InspectPoliciesResponse_DerivedRole_KIND_IMPORTED,
	}
}

// ListRuleTableRowVariables returns local and exported variables defined in a rule table row.
func ListRuleTableRowVariables(row *index.Row) []*responsev1.InspectPoliciesResponse_Variable {
	if row == nil {
		return nil
	}

	variables := make([]*responsev1.InspectPoliciesResponse_Variable, len(row.GetParams().GetOrderedVariables()))
	for i := 0; i < len(row.GetParams().GetOrderedVariables()); i++ {
		variable := row.GetParams().GetOrderedVariables()[i]
		variables[i] = &responsev1.InspectPoliciesResponse_Variable{
			Name:  variable.Name,
			Value: variable.Expr.Original,
			Kind:  responsev1.InspectPoliciesResponse_Variable_KIND_UNKNOWN,
		}
	}

	if len(variables) > 1 {
		slices.SortFunc(variables, func(a, b *responsev1.InspectPoliciesResponse_Variable) int {
			if kind := cmp.Compare(a.GetKind(), b.GetKind()); kind != 0 {
				return kind
			}

			return cmp.Compare(a.GetName(), b.GetName())
		})
	}

	return variables
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
