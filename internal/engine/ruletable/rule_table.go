// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"fmt"
	"sync"
	"time"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/cel-go/cel"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	storeReloadTimeout = 5 * time.Second
	storeFetchTimeout  = 2 * time.Second
)

type RuleTable struct {
	policyLoader             policyloader.PolicyLoader
	primaryIdx               map[string]map[string]*util.GlobMap[*util.GlobMap[[]*Row]]
	scopedResourceIdx        map[string]map[string]*util.GlobMap[struct{}]
	log                      *zap.SugaredLogger
	schemas                  map[string]*policyv1.Schemas
	meta                     map[string]*runtimev1.RuleTableMetadata
	policyDerivedRoles       map[string]map[string]*WrappedRunnableDerivedRole
	scopeMap                 map[string]struct{}
	scopeScopePermissions    map[string]policyv1.ScopePermissions
	parentRoles              map[string][]string
	parentRoleAncestorsCache map[string][]string
	rules                    []*Row
	mu                       sync.RWMutex
}

type WrappedRunnableDerivedRole struct {
	*runtimev1.RunnableDerivedRole
	Constants map[string]any
}

type Row struct {
	*runtimev1.RuleTable_RuleRow
	Params            *rowParams
	DerivedRoleParams *rowParams
	EvaluationKey     string
}

func (r *Row) Matches(scope, action string, roles []string) bool {
	if scope != r.Scope {
		return false
	}

	if r.Role != "*" {
		var hasMatch bool
		for _, role := range roles {
			if r.Role == role {
				hasMatch = true
				break
			}
		}
		if !hasMatch {
			return false
		}
	}

	if r.Action != action && !util.MatchesGlob(r.Action, action) {
		return false
	}

	return true
}

type rowParams struct {
	Key         string
	Constants   map[string]any // conditions can be converted to Go native types at build time
	CelPrograms []*CelProgram  // these need to be ordered for self referential variables at eval time
	Variables   []*runtimev1.Variable
}

type CelProgram struct {
	Prog cel.Program
	Name string
}

func NewRuleTable() *RuleTable {
	return &RuleTable{
		primaryIdx:               make(map[string]map[string]*util.GlobMap[*util.GlobMap[[]*Row]]),
		scopedResourceIdx:        make(map[string]map[string]*util.GlobMap[struct{}]),
		log:                      zap.S().Named("ruletable"),
		schemas:                  make(map[string]*policyv1.Schemas),
		meta:                     make(map[string]*runtimev1.RuleTableMetadata),
		policyDerivedRoles:       make(map[string]map[string]*WrappedRunnableDerivedRole),
		scopeMap:                 make(map[string]struct{}),
		scopeScopePermissions:    make(map[string]policyv1.ScopePermissions),
		parentRoles:              make(map[string][]string),
		parentRoleAncestorsCache: make(map[string][]string),
	}
}

func (rt *RuleTable) WithPolicyLoader(policyLoader policyloader.PolicyLoader) *RuleTable {
	rt.policyLoader = policyLoader
	return rt
}

func (rt *RuleTable) LoadPolicies(rps []*runtimev1.RunnablePolicySet) error {
	for _, rp := range rps {
		if err := rt.addPolicy(rp); err != nil {
			return err
		}
	}

	return nil
}

func (rt *RuleTable) addPolicy(rps *runtimev1.RunnablePolicySet) error {
	switch rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		return rt.addResourcePolicy(rps.GetResourcePolicy())
	case *runtimev1.RunnablePolicySet_RolePolicy:
		rt.addRolePolicy(rps.GetRolePolicy())
	}

	return nil
}

func (rt *RuleTable) addResourcePolicy(rrps *runtimev1.RunnableResourcePolicySet) error {
	sanitizedResource := namer.SanitizedResource(rrps.Meta.Resource)

	rt.schemas[rrps.Meta.Fqn] = rrps.Schemas

	policies := rrps.GetPolicies()
	if len(policies) == 0 {
		return nil
	}

	// we only process the first of resource policy sets as it's assumed parent scopes are handled in separate calls
	p := rrps.GetPolicies()[0]

	rt.meta[rrps.Meta.Fqn] = &runtimev1.RuleTableMetadata{
		Fqn:              rrps.Meta.Fqn,
		Name:             &runtimev1.RuleTableMetadata_Resource{Resource: sanitizedResource},
		Version:          rrps.Meta.Version,
		SourceAttributes: rrps.Meta.SourceAttributes,
		Annotations:      rrps.Meta.Annotations,
	}

	wrapped := make(map[string]*WrappedRunnableDerivedRole)
	for n, dr := range p.DerivedRoles {
		wrapped[n] = &WrappedRunnableDerivedRole{
			RunnableDerivedRole: dr,
			Constants:           (&structpb.Struct{Fields: dr.Constants}).AsMap(),
		}
	}
	rt.policyDerivedRoles[rrps.Meta.Fqn] = wrapped

	progs, err := getCelProgramsFromExpressions(p.OrderedVariables)
	if err != nil {
		return err
	}
	policyParameters := &rowParams{
		Key:         namer.ResourcePolicyFQN(sanitizedResource, rrps.Meta.Version, p.Scope),
		Variables:   p.OrderedVariables,
		Constants:   (&structpb.Struct{Fields: p.Constants}).AsMap(),
		CelPrograms: progs,
	}

	scopePermissions := p.ScopePermissions
	if scopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
		scopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
	}
	rt.scopeScopePermissions[p.Scope] = scopePermissions

	for _, rule := range p.Rules {
		emitOutput := rule.EmitOutput
		if emitOutput == nil && rule.Output != nil { //nolint:staticcheck
			emitOutput = &runtimev1.Output{
				When: &runtimev1.Output_When{
					RuleActivated: rule.Output, //nolint:staticcheck
				},
			}
		}

		ruleFqn := namer.RuleFQN(rt.meta[rrps.Meta.Fqn], p.Scope, rule.Name)
		evaluationKey := fmt.Sprintf("%s#%s", policyParameters.Key, ruleFqn)
		for a := range rule.Actions {
			for r := range rule.Roles {
				rt.insertRule(&Row{
					RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
						OriginFqn:        rrps.Meta.Fqn,
						Resource:         sanitizedResource,
						Role:             r,
						Action:           a,
						Condition:        rule.Condition,
						Effect:           rule.Effect,
						Scope:            p.Scope,
						ScopePermissions: scopePermissions,
						Version:          rrps.Meta.Version,
						EmitOutput:       emitOutput,
						Name:             rule.Name,
					},
					Params:        policyParameters,
					EvaluationKey: evaluationKey,
				})
			}

			// merge derived roles as roles with added conditions
			for dr := range rule.DerivedRoles {
				if rdr, ok := p.DerivedRoles[dr]; ok {
					progs, err := getCelProgramsFromExpressions(rdr.OrderedVariables)
					if err != nil {
						return err
					}
					derivedRoleParams := &rowParams{
						Key:         namer.DerivedRolesFQN(dr),
						Variables:   rdr.OrderedVariables,
						Constants:   (&structpb.Struct{Fields: rdr.Constants}).AsMap(),
						CelPrograms: progs,
					}

					evaluationKey := fmt.Sprintf("%s#%s", derivedRoleParams.Key, ruleFqn)
					for pr := range rdr.ParentRoles {
						rt.insertRule(&Row{
							RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
								OriginFqn:            rrps.Meta.Fqn,
								Resource:             sanitizedResource,
								Role:                 pr,
								Action:               a,
								Condition:            rule.Condition,
								DerivedRoleCondition: rdr.Condition,
								Effect:               rule.Effect,
								Scope:                p.Scope,
								ScopePermissions:     scopePermissions,
								Version:              rrps.Meta.Version,
								OriginDerivedRole:    dr,
								EmitOutput:           emitOutput,
								Name:                 rule.Name,
							},
							Params:            policyParameters,
							DerivedRoleParams: derivedRoleParams,
							EvaluationKey:     evaluationKey,
						})
					}
				}
			}
		}
	}

	return nil
}

func getCelProgramsFromExpressions(vars []*runtimev1.Variable) ([]*CelProgram, error) {
	progs := make([]*CelProgram, len(vars))

	for i, v := range vars {
		if v.Expr.Checked == nil {
			continue
		}

		p, err := conditions.StdEnv.Program(cel.CheckedExprToAst(v.Expr.Checked))
		if err != nil {
			return progs, err
		}

		progs[i] = &CelProgram{Name: v.Name, Prog: p}
	}

	return progs, nil
}

func (rt *RuleTable) addRolePolicy(p *runtimev1.RunnableRolePolicySet) {
	rt.scopeScopePermissions[p.Scope] = p.ScopePermissions

	version := "default"
	rt.meta[p.Meta.Fqn] = &runtimev1.RuleTableMetadata{
		Fqn:              p.Meta.Fqn,
		Name:             &runtimev1.RuleTableMetadata_Role{Role: p.Role},
		Version:          version,
		SourceAttributes: p.Meta.SourceAttributes,
		Annotations:      p.Meta.Annotations,
	}
	for resource, rl := range p.Resources {
		for idx, rule := range rl.Rules {
			evaluationKey := fmt.Sprintf("%s#%s_rule-%03d", namer.PolicyKeyFromFQN(namer.RolePolicyFQN(p.Role, p.Scope)), p.Role, idx)
			for a := range rule.AllowActions {
				rt.insertRule(&Row{
					RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
						OriginFqn:        p.Meta.Fqn,
						Role:             p.Role,
						Resource:         resource,
						Action:           a,
						Condition:        rule.Condition,
						Effect:           effectv1.Effect_EFFECT_ALLOW,
						Scope:            p.Scope,
						ScopePermissions: p.ScopePermissions,
						Version:          version,
					},
					EvaluationKey: evaluationKey,
				})
			}
		}
	}

	rt.parentRoles[p.Role] = p.ParentRoles
}

func (rt *RuleTable) insertRule(r *Row) {
	rt.scopeMap[r.Scope] = struct{}{}

	// index as `version->scope->role_glob->action_glob`
	{
		scopeMap, ok := rt.primaryIdx[r.Version]
		if !ok {
			scopeMap = make(map[string]*util.GlobMap[*util.GlobMap[[]*Row]])
			rt.primaryIdx[r.Version] = scopeMap
		}

		roleMap, ok := scopeMap[r.Scope]
		if !ok {
			roleMap = util.NewGlobMap(make(map[string]*util.GlobMap[[]*Row]))
			scopeMap[r.Scope] = roleMap
		}

		actionMap, ok := roleMap.GetWithLiteral(r.Role)
		if !ok {
			actionMap = util.NewGlobMap(make(map[string][]*Row))
			roleMap.Set(r.Role, actionMap)
		}

		rows, _ := actionMap.GetWithLiteral(r.Action)
		rows = append(rows, r)
		actionMap.Set(r.Action, rows)
	}

	// separate scopedResource index
	{
		scopeMap, ok := rt.scopedResourceIdx[r.Version]
		if !ok {
			scopeMap = make(map[string]*util.GlobMap[struct{}])
			rt.scopedResourceIdx[r.Version] = scopeMap
		}

		resourceMap, ok := scopeMap[r.Scope]
		if !ok {
			resourceMap = util.NewGlobMap(make(map[string]struct{}))
			scopeMap[r.Scope] = resourceMap
		}

		resourceMap.Set(r.Resource, struct{}{})
	}

	rt.rules = append(rt.rules, r)
}

func (rt *RuleTable) deletePolicy(rps *runtimev1.RunnablePolicySet) {
	// TODO(saml) rebuilding/reassigning the whole row slice on each delete is hugely inefficient.
	// Perhaps we could mark as `deleted` and periodically purge the deleted rows.
	// However, it's unlikely this bespoke table implementation will be around long enough to worry about this.

	rt.mu.Lock()
	defer rt.mu.Unlock()

	deletedFqn := rps.Fqn
	versionSet := make(map[string]struct{})
	scopeSet := make(map[string]struct{})

	newRules := []*Row{}
	for _, r := range rt.rules {
		if r.OriginFqn != deletedFqn {
			newRules = append(newRules, r)
			versionSet[r.Version] = struct{}{}
			scopeSet[r.Scope] = struct{}{}
		}
	}
	rt.rules = newRules

	delete(rt.schemas, deletedFqn)
	delete(rt.meta, deletedFqn)

	var version, scope string
	switch rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		rp := rps.GetResourcePolicy()
		version = rp.Meta.Version
		scope = rp.Policies[0].Scope
	case *runtimev1.RunnablePolicySet_RolePolicy:
		rlp := rps.GetRolePolicy()
		version = "default" // TODO(saml)
		scope = rlp.Scope

		delete(rt.parentRoles, rlp.Role)
		delete(rt.parentRoleAncestorsCache, rlp.Role)
	}

	if _, ok := versionSet[version]; !ok {
		delete(rt.primaryIdx, version)
		delete(rt.scopedResourceIdx, version)
	}

	if _, ok := scopeSet[scope]; !ok {
		delete(rt.scopeMap, scope)
		delete(rt.scopeScopePermissions, scope)
	}
}

func (rt *RuleTable) purge() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.rules = []*Row{}
	rt.parentRoles = make(map[string][]string)
	rt.schemas = make(map[string]*policyv1.Schemas)

	rt.scopeMap = make(map[string]struct{})
	rt.primaryIdx = make(map[string]map[string]*util.GlobMap[*util.GlobMap[[]*Row]])
	rt.scopedResourceIdx = make(map[string]map[string]*util.GlobMap[struct{}])
	rt.parentRoleAncestorsCache = make(map[string][]string)
}

func (rt *RuleTable) Len() int {
	return len(rt.rules)
}

func (rt *RuleTable) GetDerivedRoles(fqn string) map[string]*WrappedRunnableDerivedRole {
	return rt.policyDerivedRoles[fqn]
}

func (rt *RuleTable) GetAllScopes(scope, resource, version string) ([]string, string, string) {
	var firstPolicyKey, firstFqn string
	var scopes []string
	if rt.ScopeExists(scope) {
		firstFqn = namer.ResourcePolicyFQN(resource, version, scope)
		firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
		scopes = append(scopes, scope)
	}

	for i := len(scope) - 1; i >= 0; i-- {
		if scope[i] == '.' || i == 0 {
			partialScope := scope[:i]
			if rt.ScopeExists(partialScope) {
				scopes = append(scopes, partialScope)
				if firstPolicyKey == "" {
					firstFqn = namer.ResourcePolicyFQN(resource, version, partialScope)
					firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
				}
			}
		}
	}

	return scopes, firstPolicyKey, firstFqn
}

func (rt *RuleTable) ScopedResourceExists(version, resource string, scopes []string) bool {
	if scopeMap, ok := rt.scopedResourceIdx[version]; ok {
		for _, scope := range scopes {
			if resourceMap, ok := scopeMap[scope]; ok {
				if _, ok := resourceMap.Get(resource); ok {
					return true
				}
			}
		}
	}

	return false
}

func (rt *RuleTable) ScopedRoleExists(version, scope, role string) bool {
	if scopeMap, ok := rt.primaryIdx[version]; ok {
		if roleMap, ok := scopeMap[scope]; ok {
			if _, ok := roleMap.Get(role); ok {
				return true
			}
		}
	}

	return false
}

func (rt *RuleTable) GetRows(version, resource string, scopes, roles, actions []string) []*Row {
	res := []*Row{}

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if scopeSet, ok := rt.primaryIdx[version]; ok {
		for _, scope := range scopes {
			if roleSet, ok := scopeSet[scope]; ok {
				for _, role := range roles {
					for _, actionSet := range roleSet.GetMerged(role) {
						for _, action := range actions {
							for _, rules := range actionSet.GetMerged(action) {
								for _, r := range rules {
									if util.MatchesGlob(r.Resource, resource) {
										res = append(res, r)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return res
}

func (rt *RuleTable) GetParentRoles(roles []string) []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// recursively collect all parent roles, caching the flat list on the very first traversal for
	// each role within the ruletable
	parentRoles := make([]string, len(roles))
	copy(parentRoles, roles)
	for _, role := range roles {
		var roleParents []string
		if c, ok := rt.parentRoleAncestorsCache[role]; ok {
			roleParents = c
		} else {
			visited := make(map[string]struct{})
			roleParentsSet := make(map[string]struct{})
			rt.collectParentRoles(role, roleParentsSet, visited)
			roleParents = make([]string, 0, len(roleParentsSet))
			for r := range roleParentsSet {
				roleParents = append(roleParents, r)
			}
			rt.parentRoleAncestorsCache[role] = roleParents
		}
		parentRoles = append(parentRoles, roleParents...) //nolint:makezero
	}
	return parentRoles
}

func (rt *RuleTable) collectParentRoles(role string, parentRoleSet, visited map[string]struct{}) {
	if _, seen := visited[role]; seen {
		return
	}
	visited[role] = struct{}{}

	if prs, ok := rt.parentRoles[role]; ok {
		for _, pr := range prs {
			parentRoleSet[pr] = struct{}{}
			rt.collectParentRoles(pr, parentRoleSet, visited)
		}
	}
}

func (rt *RuleTable) ScopeExists(scope string) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	_, ok := rt.scopeMap[scope]
	return ok
}

func (rt *RuleTable) GetScopeScopePermissions(scope string) policyv1.ScopePermissions {
	return rt.scopeScopePermissions[scope]
}

func (rt *RuleTable) GetSchema(fqn string) *policyv1.Schemas {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if s, ok := rt.schemas[fqn]; ok {
		return s
	}

	return nil
}

func (rt *RuleTable) GetMeta(fqn string) *runtimev1.RuleTableMetadata {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if s, ok := rt.meta[fqn]; ok {
		return s
	}

	return nil
}

func (rt *RuleTable) SubscriberID() string {
	return "engine.RuleTable"
}

func (rt *RuleTable) OnStorageEvent(events ...storage.Event) {
	for _, evt := range events {
		switch evt.Kind {
		case storage.EventReload:
			rt.log.Info("Reloading ruletable")
			if err := rt.triggerReload(); err != nil {
				rt.log.Warnw("Error while processing reload event", "event", evt, "error", err)
			}
		case storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
			rt.log.Debugw("Processing storage event", "event", evt)
			if err := rt.processPolicyEvent(evt); err != nil {
				rt.log.Warnw("Error while processing storage event", "event", evt, "error", err)
			}
		default:
			rt.log.Debugw("Ignoring storage event", "event", evt)
		}
	}
}

func (rt *RuleTable) triggerReload() error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), storeReloadTimeout)
	defer cancelFunc()

	rpss, err := rt.policyLoader.GetAll(ctx)
	if err != nil {
		return err
	}

	rt.purge()

	return rt.LoadPolicies(rpss)
}

func (rt *RuleTable) processPolicyEvent(ev storage.Event) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), storeFetchTimeout)
	defer cancelFunc()

	rps, err := rt.policyLoader.GetFirstMatch(ctx, []namer.ModuleID{ev.PolicyID})
	if err != nil {
		return err
	}

	rt.deletePolicy(rps)

	if ev.Kind == storage.EventAddOrUpdatePolicy {
		if err := rt.addPolicy(rps); err != nil {
			return err
		}
	}

	return nil
}
