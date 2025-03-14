// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"

	"github.com/google/cel-go/cel"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const allowActionsIdxKey = "\x00_cerbos_reserved_allow_actions"

var errNoPoliciesMatched = errors.New("no matching policies")

type RuleTable struct {
	policyLoader policyloader.PolicyLoader
	// version -> scope -> role -> action -> []rows
	primaryIdx            map[string]map[string]*util.GlobMap[*util.GlobMap[[]*Row]]
	scopedResourceIdx     map[string]map[string]*util.GlobMap[struct{}]
	log                   *zap.SugaredLogger
	schemas               map[namer.ModuleID]*policyv1.Schemas
	meta                  map[namer.ModuleID]*runtimev1.RuleTableMetadata
	policyDerivedRoles    map[namer.ModuleID]map[string]*WrappedRunnableDerivedRole
	storeQueryRegister    map[namer.ModuleID]bool
	scopeMap              map[string]struct{}
	scopeScopePermissions map[string]policyv1.ScopePermissions
	// role policies are per-scope, so the maps takes the form `map[scope]map[role][]roles`
	parentRoles              map[string]map[string][]string
	parentRoleAncestorsCache map[string]map[string][]string
	mu                       sync.RWMutex
}

type WrappedRunnableDerivedRole struct {
	*runtimev1.RunnableDerivedRole
	Constants map[string]any
}

type Row struct {
	*runtimev1.RuleTable_RuleRow
	Params                     *rowParams
	DerivedRoleParams          *rowParams
	EvaluationKey              string
	OriginModuleID             namer.ModuleID
	NoMatchForScopePermissions bool
}

func (r *Row) Matches(scope, action string, roles []string) bool {
	if scope != r.Scope {
		return false
	}

	if r.Role != "*" {
		if !slices.Contains(roles, r.Role) {
			return false
		}
	}

	a := r.GetAction()
	if a != action && !util.MatchesGlob(a, action) {
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

func NewRuleTable(policyLoader policyloader.PolicyLoader) *RuleTable {
	return &RuleTable{
		primaryIdx:               make(map[string]map[string]*util.GlobMap[*util.GlobMap[[]*Row]]),
		scopedResourceIdx:        make(map[string]map[string]*util.GlobMap[struct{}]),
		log:                      zap.S().Named("ruletable"),
		schemas:                  make(map[namer.ModuleID]*policyv1.Schemas),
		meta:                     make(map[namer.ModuleID]*runtimev1.RuleTableMetadata),
		policyDerivedRoles:       make(map[namer.ModuleID]map[string]*WrappedRunnableDerivedRole),
		storeQueryRegister:       make(map[namer.ModuleID]bool),
		scopeMap:                 make(map[string]struct{}),
		scopeScopePermissions:    make(map[string]policyv1.ScopePermissions),
		parentRoles:              make(map[string]map[string][]string),
		parentRoleAncestorsCache: make(map[string]map[string][]string),
		policyLoader:             policyLoader,
	}
}

func (rt *RuleTable) LazyLoad(ctx context.Context, resource, policyVer, scope string, inputRoles []string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// A matching scope must have at least one resource or role policy or a mixture of both.
	// Add rules for policies at all scope levels.
	// We duplicate rows for all role policy parent roles recursively.
	//
	// Rule table resource policies are added as individual units rather than as compilation units.
	// Therefore, we need to retrieve the compilation unit for each scope, remove all bar the first policy,
	// and pass all individually to the loadPolicies method.
	toLoad := []*runtimev1.RunnablePolicySet{}

	// we don't want to add retrieved mod IDs to the cache until the rule table has been successfully updated
	registryBuffer := make(map[namer.ModuleID]bool)

	checkRegisters := func(modID namer.ModuleID) (bool, bool) {
		if policyExists, isQueried := registryBuffer[modID]; isQueried {
			return policyExists, isQueried
		}

		policyExists, isQueried := rt.storeQueryRegister[modID]
		return policyExists, isQueried
	}

	// we force lenientScopeSearch when retrieving resource policy sets as lenient scope search is enforced
	// in the evaluator function. Therefore, to prevent duplicate rows in the rule table, we check the returned
	// policy scope before adding to `toLoad`
	addScopedPolicyRules := func(partialScope string) error {
		var rps *runtimev1.RunnablePolicySet

		cachedPolicyCount := 0

		resourceModID := namer.ResourcePolicyModuleID(resource, policyVer, partialScope)

		// Check to see if the store has already been queried for the given parameters.
		if policyExists, isQueried := checkRegisters(resourceModID); !isQueried { //nolint:nestif
			var err error
			rps, err = rt.getResourcePolicySet(ctx, resource, policyVer, partialScope, true)
			if err != nil {
				return err
			}

			if rps == nil {
				registryBuffer[resourceModID] = false
				// we used lenientScopeSearch, so we can assert that no policies exist for all child scopes
				for s := range namer.ScopeParents(scope) {
					registryBuffer[namer.ResourcePolicyModuleID(resource, policyVer, s)] = false
				}
			} else {
				// check the first policy scope
				p := rps.GetResourcePolicy().GetPolicies()[0]

				// lenientScopeSearch might return a parent policy which we've already added--don't load if this is the case
				if p.Scope != partialScope {
					// the target scoped resource policy didn't exist, so register the query with a false hit
					registryBuffer[resourceModID] = false
					// also for those scopes between
					for s := range namer.ScopeParents(partialScope) {
						if s == p.Scope {
							break
						}
						registryBuffer[namer.ResourcePolicyModuleID(resource, policyVer, partialScope)] = false
					}

					resourceModID = namer.ResourcePolicyModuleID(resource, policyVer, p.Scope)
				}

				if _, exists := checkRegisters(resourceModID); !exists {
					toLoad = append(toLoad, rps)
					registryBuffer[resourceModID] = true
				} else {
					cachedPolicyCount++
				}
			}
		} else if policyExists {
			cachedPolicyCount++
		}

		missingInputRoles := make([]string, 0, len(inputRoles))
		for _, r := range inputRoles {
			roleModID := namer.RolePolicyModuleID(r, partialScope)
			if policyExists, isQueried := checkRegisters(roleModID); !isQueried {
				missingInputRoles = append(missingInputRoles, r)
			} else if policyExists {
				cachedPolicyCount++
			}
		}

		rlps, err := rt.getRolePolicySets(ctx, partialScope, missingInputRoles)
		if err != nil {
			return err
		}

		existingRolePolicies := make(map[string]struct{}, len(rlps))
		for _, rlp := range rlps {
			modID := namer.GenModuleIDFromFQN(rlp.GetFqn())
			registryBuffer[modID] = true
			existingRolePolicies[rlp.GetRolePolicy().GetRole()] = struct{}{}
		}

		for _, r := range missingInputRoles {
			if _, exists := existingRolePolicies[r]; !exists {
				registryBuffer[namer.RolePolicyModuleID(r, partialScope)] = false
			}
		}

		if (rps == nil || len(rps.GetResourcePolicy().GetPolicies()) == 0) && len(rlps) == 0 && cachedPolicyCount == 0 {
			return errNoPoliciesMatched
		}

		toLoad = append(toLoad, rlps...)

		return nil
	}

	if err := addScopedPolicyRules(scope); err != nil {
		if errors.Is(err, errNoPoliciesMatched) {
			return nil
		}
		return err
	}

	for s := range namer.ScopeParents(scope) {
		if err := addScopedPolicyRules(s); err != nil {
			if errors.Is(err, errNoPoliciesMatched) {
				break
			}
			return err
		}
	}

	if len(toLoad) == 0 {
		return nil
	}

	if err := rt.loadPolicies(toLoad); err != nil {
		return err
	}

	maps.Copy(rt.storeQueryRegister, registryBuffer)

	return nil
}

func (rt *RuleTable) getResourcePolicySet(ctx context.Context, resource, policyVer, scope string, lenientScopeSearch bool) (*runtimev1.RunnablePolicySet, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.GetResourcePolicy")
	defer span.End()
	span.SetAttributes(tracing.PolicyName(resource), tracing.PolicyVersion(policyVer), tracing.PolicyScope(scope))

	resourceModIDs := namer.ScopedResourcePolicyModuleIDs(resource, policyVer, scope, lenientScopeSearch)
	rps, err := rt.policyLoader.GetFirstMatch(ctx, resourceModIDs)
	if err != nil {
		tracing.MarkFailed(span, http.StatusInternalServerError, err)
		return nil, err
	}

	return rps, nil
}

func (rt *RuleTable) getRolePolicySets(ctx context.Context, scope string, roles []string) ([]*runtimev1.RunnablePolicySet, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.GetRolePolicies")
	defer span.End()
	span.SetAttributes(tracing.PolicyScope(scope))

	processedRoles := make(map[string]struct{})
	sets := []*runtimev1.RunnablePolicySet{}

	// we recursively retrieve all role policies defined within parent roles
	// (parent roles can be base level or role policy roles)
	//
	// TODO: to avoid repeat unconstrained (and potentially expensive) recursions,
	// we could cache the result here and invalidate if the index changes. This might
	// not be relevant if we rethink how the index is implemented down the line
	var getPolicies func([]string, map[string]struct{}) error

	getPolicies = func(roles []string, processedRoles map[string]struct{}) error {
		roleModIDs := make([]namer.ModuleID, 0, len(roles))
		for _, r := range roles {
			if _, ok := processedRoles[r]; !ok {
				roleModIDs = append(roleModIDs, namer.RolePolicyModuleID(r, scope))
				processedRoles[r] = struct{}{}
			}
		}

		currSets, err := rt.policyLoader.GetAllMatching(ctx, roleModIDs)
		if err != nil {
			tracing.MarkFailed(span, http.StatusInternalServerError, err)
			return err
		}

		for _, r := range currSets {
			rp := r.GetRolePolicy()

			err := getPolicies(rp.GetParentRoles(), processedRoles)
			if err != nil {
				return err
			}

			sets = append(sets, r)
		}
		return nil
	}

	if err := getPolicies(roles, processedRoles); err != nil {
		return nil, err
	}

	return sets, nil
}

func (rt *RuleTable) loadPolicies(rps []*runtimev1.RunnablePolicySet) error {
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

	policies := rrps.GetPolicies()
	if len(policies) == 0 {
		return nil
	}

	// we only process the first of resource policy sets as it's assumed parent scopes are handled in separate calls
	p := rrps.GetPolicies()[0]

	moduleID := namer.GenModuleIDFromFQN(rrps.Meta.Fqn)
	rt.schemas[moduleID] = rrps.Schemas
	rt.meta[moduleID] = &runtimev1.RuleTableMetadata{
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
	rt.policyDerivedRoles[moduleID] = wrapped

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

		ruleFqn := namer.RuleFQN(rt.meta[moduleID], p.Scope, rule.Name)
		evaluationKey := fmt.Sprintf("%s#%s", policyParameters.Key, ruleFqn)
		for a := range rule.Actions {
			for r := range rule.Roles {
				row := &Row{
					RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
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
					},
					Params:         policyParameters,
					EvaluationKey:  evaluationKey,
					OriginModuleID: moduleID,
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

				rt.insertRule(row)
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
						row := &Row{
							RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
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
							},
							Params:            policyParameters,
							DerivedRoleParams: derivedRoleParams,
							EvaluationKey:     evaluationKey,
							OriginModuleID:    moduleID,
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

						rt.insertRule(row)
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
	version := "default" //nolint:goconst
	moduleID := namer.GenModuleIDFromFQN(p.Meta.Fqn)
	rt.meta[moduleID] = &runtimev1.RuleTableMetadata{
		Fqn:              p.Meta.Fqn,
		Name:             &runtimev1.RuleTableMetadata_Role{Role: p.Role},
		Version:          version,
		SourceAttributes: p.Meta.SourceAttributes,
		Annotations:      p.Meta.Annotations,
	}
	for resource, rl := range p.Resources {
		for idx, rule := range rl.Rules {
			rt.insertRule(&Row{
				RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
					OriginFqn: p.Meta.Fqn,
					Role:      p.Role,
					Resource:  resource,
					ActionSet: &runtimev1.RuleTable_RuleRow_AllowActions_{
						AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{
							Actions: rule.AllowActions,
						},
					},
					Condition: rule.Condition,
					Scope:     p.Scope,
					Version:   version,
				},
				EvaluationKey:  fmt.Sprintf("%s#%s_rule-%03d", namer.PolicyKeyFromFQN(namer.RolePolicyFQN(p.Role, p.Scope)), p.Role, idx),
				OriginModuleID: moduleID,
			})
		}
	}

	if _, ok := rt.parentRoles[p.Scope]; !ok {
		rt.parentRoles[p.Scope] = make(map[string][]string)
	}

	rt.parentRoles[p.Scope][p.Role] = p.ParentRoles
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

		action := r.GetAction()
		if len(r.GetAllowActions().GetActions()) > 0 {
			action = allowActionsIdxKey
		}

		rows, _ := actionMap.GetWithLiteral(action)
		rows = append(rows, r)
		actionMap.Set(action, rows)
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
}

func (rt *RuleTable) deletePolicy(moduleID namer.ModuleID) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	meta := rt.meta[moduleID]
	if meta == nil {
		return
	}

	rt.log.Debugf("Deleting policy %s", meta.GetFqn())

	rt.storeQueryRegister[moduleID] = false

	for version, scopeMap := range rt.primaryIdx {
		for scope, roleMap := range scopeMap {
			scopedParentRoleAncestors := rt.parentRoleAncestorsCache[scope]
			scopedParentRoles := rt.parentRoles[scope]

			for role, actionMap := range roleMap.GetAll() {
				for action, rules := range actionMap.GetAll() {
					newRules := make([]*Row, 0, len(rules))
					for _, r := range rules {
						if r.OriginModuleID != moduleID {
							newRules = append(newRules, r)
						} else {
							rt.log.Debugf("Dropping rule %s", r.GetOriginFqn())
						}
					}

					if len(newRules) > 0 {
						actionMap.Set(action, newRules)
					} else {
						actionMap.DeleteLiteral(action)
					}
				}

				if actionMap.Len() == 0 {
					roleMap.DeleteLiteral(role)
					delete(scopedParentRoleAncestors, role)
					delete(scopedParentRoles, role)
				}
			}

			if roleMap.Len() == 0 {
				delete(scopeMap, scope)
				delete(rt.scopeMap, scope)
				delete(rt.scopeScopePermissions, scope)
				delete(rt.parentRoleAncestorsCache, scope)
				delete(rt.parentRoles, scope)
			}
		}

		if len(scopeMap) == 0 {
			delete(rt.primaryIdx, version)
			delete(rt.scopedResourceIdx, version)
		}
	}

	delete(rt.schemas, moduleID)
	delete(rt.meta, moduleID)
	delete(rt.policyDerivedRoles, moduleID)
}

func (rt *RuleTable) purge() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	clear(rt.meta)
	clear(rt.parentRoleAncestorsCache)
	clear(rt.parentRoles)
	clear(rt.policyDerivedRoles)
	clear(rt.primaryIdx)
	clear(rt.schemas)
	clear(rt.scopeMap)
	clear(rt.scopeScopePermissions)
	clear(rt.scopedResourceIdx)
	clear(rt.storeQueryRegister)
}

func (rt *RuleTable) GetDerivedRoles(fqn string) map[string]*WrappedRunnableDerivedRole {
	return rt.policyDerivedRoles[namer.GenModuleIDFromFQN(fqn)]
}

func (rt *RuleTable) GetAllScopes(scope, resource, version string) ([]string, string, string) {
	var firstPolicyKey, firstFqn string
	var scopes []string
	if rt.ScopeExists(scope) {
		firstFqn = namer.ResourcePolicyFQN(resource, version, scope)
		firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
		scopes = append(scopes, scope)
	}

	for s := range namer.ScopeParents(scope) {
		if rt.ScopeExists(s) {
			scopes = append(scopes, s)
			if firstPolicyKey == "" {
				firstFqn = namer.ResourcePolicyFQN(resource, version, s)
				firstPolicyKey = namer.PolicyKeyFromFQN(firstFqn)
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

	if scopeSet, ok := rt.primaryIdx[version]; ok { //nolint:nestif
		for _, scope := range scopes {
			if roleSet, ok := scopeSet[scope]; ok {
				for _, role := range roles {
					roleFqn := namer.RolePolicyFQN(role, scope)
					for _, actionSet := range roleSet.GetMerged(role) {
						if ars, ok := actionSet.GetWithLiteral(allowActionsIdxKey); ok {
							actionMatchedRows := util.NewGlobMap(make(map[string][]*Row))
							// retrieve actions mapped to all effectual rows
							for _, ar := range ars {
								if util.MatchesGlob(ar.Resource, resource) {
									for a := range ar.GetAllowActions().GetActions() {
										rows, _ := actionMatchedRows.Get(a)
										rows = append(rows, ar)
										actionMatchedRows.Set(a, rows)
									}
								}
							}

							for _, action := range actions {
								matchedRows := []*Row{}
								for _, rows := range actionMatchedRows.GetMerged(action) {
									matchedRows = append(matchedRows, rows...)
								}
								if len(matchedRows) == 0 {
									// add a blanket DENY for non matching actions
									res = append(res, &Row{
										RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
											ActionSet: &runtimev1.RuleTable_RuleRow_Action{
												Action: action,
											},
											OriginFqn: roleFqn,
											Resource:  resource,
											Role:      role,
											Effect:    effectv1.Effect_EFFECT_DENY,
											Scope:     scope,
											Version:   version,
										},
										NoMatchForScopePermissions: true,
									})
								} else {
									for _, ar := range matchedRows {
										// Don't bother adding a rule if there's no condition.
										// Otherwise, we invert the condition and set a DENY
										if ar.Condition != nil {
											res = append(res, &Row{
												RuleTable_RuleRow: &runtimev1.RuleTable_RuleRow{
													ActionSet: &runtimev1.RuleTable_RuleRow_Action{
														Action: action,
													},
													OriginFqn: ar.OriginFqn,
													Resource:  resource,
													Condition: &runtimev1.Condition{
														Op: &runtimev1.Condition_None{
															None: &runtimev1.Condition_ExprList{
																Expr: []*runtimev1.Condition{ar.Condition},
															},
														},
													},
													Role:             ar.Role,
													Effect:           effectv1.Effect_EFFECT_DENY,
													Scope:            scope,
													ScopePermissions: policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS,
													Version:          version,
												},
												EvaluationKey:  ar.EvaluationKey,
												OriginModuleID: ar.OriginModuleID,
											})
										}
									}
								}
							}
						}

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

func (rt *RuleTable) GetParentRoles(scope string, roles []string) []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// recursively collect all parent roles, caching the flat list on the very first traversal for
	// each role within the ruletable
	parentRoles := make([]string, len(roles))
	copy(parentRoles, roles)

	parentRoleAncestorsCache, ok := rt.parentRoleAncestorsCache[scope]
	if !ok {
		parentRoleAncestorsCache = make(map[string][]string)
		rt.parentRoleAncestorsCache[scope] = parentRoleAncestorsCache
	}

	for _, role := range roles {
		var roleParents []string
		if c, ok := parentRoleAncestorsCache[role]; ok {
			roleParents = c
		} else {
			visited := make(map[string]struct{})
			roleParentsSet := make(map[string]struct{})
			rt.collectParentRoles(scope, role, roleParentsSet, visited)
			roleParents = make([]string, 0, len(roleParentsSet))
			for r := range roleParentsSet {
				roleParents = append(roleParents, r)
			}
			parentRoleAncestorsCache[role] = roleParents
		}
		parentRoles = append(parentRoles, roleParents...) //nolint:makezero
	}

	return parentRoles
}

func (rt *RuleTable) collectParentRoles(scope, role string, parentRoleSet, visited map[string]struct{}) {
	if _, seen := visited[role]; seen {
		return
	}
	visited[role] = struct{}{}

	if parentRoles, ok := rt.parentRoles[scope]; ok {
		if prs, ok := parentRoles[role]; ok {
			for _, pr := range prs {
				parentRoleSet[pr] = struct{}{}
				rt.collectParentRoles(scope, pr, parentRoleSet, visited)
			}
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

	if s, ok := rt.schemas[namer.GenModuleIDFromFQN(fqn)]; ok {
		return s
	}

	return nil
}

func (rt *RuleTable) GetMeta(fqn string) *runtimev1.RuleTableMetadata {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if s, ok := rt.meta[namer.GenModuleIDFromFQN(fqn)]; ok {
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
			rt.log.Info("Purging ruletable")
			rt.purge()
		case storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
			rt.log.Debugw("Processing storage event", "event", evt)
			rt.processPolicyEvent(evt)
		default:
			rt.log.Debugw("Ignoring storage event", "event", evt)
		}
	}
}

func (rt *RuleTable) processPolicyEvent(ev storage.Event) {
	rt.deletePolicy(ev.PolicyID)
	if ev.OldPolicyID != nil {
		rt.deletePolicy(*ev.OldPolicyID)
	}

	if ev.Kind == storage.EventAddOrUpdatePolicy {
		// we load lazily--invalidating the query register ensures the store gets
		// queried again the next time.
		delete(rt.storeQueryRegister, ev.PolicyID)
	}
}
