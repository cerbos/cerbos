package ruletable

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	celast "github.com/google/cel-go/common/ast"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/ruletable/internal"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

const (
	allowActionsIdxKey      = "\x00_cerbos_reserved_allow_actions"
	conditionNotSatisfied   = "Condition not satisfied"
	noMatchScopePermissions = "NO_MATCH_FOR_SCOPE_PERMISSIONS"
	noPolicyMatch           = "NO_MATCH"
)

func AddPolicy(rt *runtimev1.RuleTable, rps *runtimev1.RunnablePolicySet) {
	switch rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		addResourcePolicy(rt, rps.GetResourcePolicy())
	case *runtimev1.RunnablePolicySet_RolePolicy:
		addRolePolicy(rt, rps.GetRolePolicy())
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		addPrincipalPolicy(rt, rps.GetPrincipalPolicy())
	}
}

func addPrincipalPolicy(rt *runtimev1.RuleTable, rpps *runtimev1.RunnablePrincipalPolicySet) error {
	principalID := rpps.Meta.Principal

	policies := rpps.GetPolicies()
	if len(policies) == 0 {
		return nil
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
				Resource:  resource,
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
				OrderedVariables: p.OrderedVariables,
				Constants:        p.Constants,
				EvaluationKey:    evaluationKey,
				PolicyKind:       policyv1.Kind_KIND_PRINCIPAL,
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

			insertRule(rt, row)
		}
	}

	return nil
}

func addResourcePolicy(rt *runtimev1.RuleTable, rrps *runtimev1.RunnableResourcePolicySet) {
	sanitizedResource := namer.SanitizedResource(rrps.Meta.Resource)

	policies := rrps.GetPolicies()
	if len(policies) == 0 {
		return
	}

	// we only process the first of resource policy sets as it's assumed parent scopes are handled in separate calls
	p := rrps.GetPolicies()[0]

	moduleID := namer.GenModuleIDFromFQN(rrps.Meta.Fqn)
	rt.Schemas[moduleID.RawValue()] = rrps.Schemas
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
					OrderedVariables: p.OrderedVariables,
					Constants:        p.Constants,
					EvaluationKey:    evaluationKey,
					PolicyKind:       policyv1.Kind_KIND_RESOURCE,
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

				insertRule(rt, row)
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
							Condition:                   rule.Condition,
							DerivedRoleCondition:        rdr.Condition,
							Effect:                      rule.Effect,
							Scope:                       p.Scope,
							ScopePermissions:            scopePermissions,
							Version:                     rrps.Meta.Version,
							OriginDerivedRole:           dr,
							EmitOutput:                  emitOutput,
							Name:                        rule.Name,
							OrderedVariables:            p.OrderedVariables,
							Constants:                   p.Constants,
							DerivedRoleOrderedVariables: rdr.OrderedVariables,
							DerivedRoleConstants:        rdr.Constants,
							EvaluationKey:               evaluationKey,
							PolicyKind:                  policyv1.Kind_KIND_RESOURCE,
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

						insertRule(rt, row)
					}
				}
			}
		}
	}
}

func addRolePolicy(rt *runtimev1.RuleTable, p *runtimev1.RunnableRolePolicySet) {
	version := "default" //nolint:goconst
	moduleID := namer.GenModuleIDFromFQN(p.Meta.Fqn)
	rt.Meta[moduleID.RawValue()] = &runtimev1.RuleTableMetadata{
		Fqn:              p.Meta.Fqn,
		Name:             &runtimev1.RuleTableMetadata_Role{Role: p.Role},
		Version:          version,
		SourceAttributes: p.Meta.SourceAttributes,
		Annotations:      p.Meta.Annotations,
	}
	for resource, rl := range p.Resources {
		for idx, rule := range rl.Rules {
			insertRule(rt, &runtimev1.RuleTable_RuleRow{
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
				Version:        version,
				EvaluationKey:  fmt.Sprintf("%s#%s_rule-%03d", namer.PolicyKeyFromFQN(namer.RolePolicyFQN(p.Role, p.Scope)), p.Role, idx),
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
}

// TODO(saml) make idempotent
func insertRule(rt *runtimev1.RuleTable, r *runtimev1.RuleTable_RuleRow) {
	rt.Rules = append(rt.Rules, r)
}

type RuleTableManager struct {
	*runtimev1.RuleTable
	log                      *zap.SugaredLogger
	schemaMgr                schema.Manager
	primaryIdx               map[string]map[string]*util.GlobMap[*util.GlobMap[[]*Row]] // TODO(saml) POST
	principalScopeMap        map[string]struct{}                                        // TODO(saml) POST
	resourceScopeMap         map[string]struct{}                                        // TODO(saml) POST
	scopeScopePermissions    map[string]policyv1.ScopePermissions                       // TODO(saml) POST
	parentRoleAncestorsCache map[string]map[string][]string                             // TODO(saml) POST
	policyDerivedRoles       map[namer.ModuleID]map[string]*WrappedRunnableDerivedRole  // TODO(saml) PRE + POST(? for WrappedRunnableDerivedRole)
	mu                       sync.RWMutex                                               // TODO(saml) not required in static
}

type Row struct {
	*runtimev1.RuleTable_RuleRow
	Params                     *rowParams
	DerivedRoleParams          *rowParams
	NoMatchForScopePermissions bool
}

func (r *Row) Matches(pt policyv1.Kind, scope, action, principalID string, roles []string) bool {
	if r.PolicyKind != pt {
		return false
	}

	if pt == policyv1.Kind_KIND_PRINCIPAL && r.Principal != principalID {
		return false
	}

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

type WrappedRunnableDerivedRole struct {
	*runtimev1.RunnableDerivedRole
	Constants map[string]any
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

func NewRuleTableManager(rt *runtimev1.RuleTable, schemaMgr schema.Manager) (*RuleTableManager, error) {
	mgr := &RuleTableManager{
		RuleTable:                rt,
		log:                      zap.S().Named("ruletable"),
		schemaMgr:                schemaMgr,
		primaryIdx:               make(map[string]map[string]*util.GlobMap[*util.GlobMap[[]*Row]]),
		policyDerivedRoles:       make(map[namer.ModuleID]map[string]*WrappedRunnableDerivedRole),
		principalScopeMap:        make(map[string]struct{}),
		resourceScopeMap:         make(map[string]struct{}),
		scopeScopePermissions:    make(map[string]policyv1.ScopePermissions),
		parentRoleAncestorsCache: make(map[string]map[string][]string),
	}

	for _, r := range rt.Rules {
		row := &Row{
			RuleTable_RuleRow: r,
		}

		switch r.PolicyKind {
		case policyv1.Kind_KIND_RESOURCE:
			if !r.FromRolePolicy {
				params, err := generateRowParams(r.OriginFqn, r.OrderedVariables, r.Constants)
				if err != nil {
					return nil, err
				}
				row.Params = params
				if r.OriginDerivedRole != "" {
					drParams, err := generateRowParams(namer.DerivedRolesFQN(r.OriginDerivedRole), r.DerivedRoleOrderedVariables, r.DerivedRoleConstants)
					if err != nil {
						return nil, err
					}
					row.DerivedRoleParams = drParams
				}

				modID := namer.GenModuleIDFromFQN(r.OriginFqn)
				if pdr, ok := rt.PolicyDerivedRoles[modID.RawValue()]; ok {
					if _, ok := mgr.policyDerivedRoles[modID]; !ok {
						mgr.policyDerivedRoles[modID] = make(map[string]*WrappedRunnableDerivedRole)
					}

					for n, dr := range pdr.DerivedRoles {
						mgr.policyDerivedRoles[modID][n] = &WrappedRunnableDerivedRole{
							RunnableDerivedRole: dr,
							Constants:           (&structpb.Struct{Fields: dr.Constants}).AsMap(),
						}
					}
				}
			} else {

			}
		case policyv1.Kind_KIND_PRINCIPAL:
			params, err := generateRowParams(r.OriginFqn, r.OrderedVariables, r.Constants)
			if err != nil {
				return nil, err
			}
			row.Params = params
		}

		mgr.indexRule(row)
	}

	// rules are now indexed, we can clear up any unnecessary transport state
	clear(mgr.RuleTable.Rules)
	clear(mgr.RuleTable.PolicyDerivedRoles)

	return mgr, nil
}

func generateRowParams(fqn string, orderedVariables []*runtimev1.Variable, constants map[string]*structpb.Value) (*rowParams, error) {
	progs, err := getCelProgramsFromExpressions(orderedVariables)
	if err != nil {
		return nil, err
	}

	return &rowParams{
		Key:         fqn,
		Variables:   orderedVariables,
		Constants:   (&structpb.Struct{Fields: constants}).AsMap(),
		CelPrograms: progs,
	}, nil
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

func (rt *RuleTableManager) indexRule(r *Row) {
	if r.ScopePermissions != policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
		rt.scopeScopePermissions[r.Scope] = r.ScopePermissions
	}

	switch r.PolicyKind { //nolint:exhaustive
	case policyv1.Kind_KIND_PRINCIPAL:
		rt.principalScopeMap[r.Scope] = struct{}{}
	case policyv1.Kind_KIND_RESOURCE:
		rt.resourceScopeMap[r.Scope] = struct{}{}
	}

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
}

func (rt *RuleTableManager) GetDerivedRoles(fqn string) map[string]*WrappedRunnableDerivedRole {
	return rt.policyDerivedRoles[namer.GenModuleIDFromFQN(fqn)]
}

func (rt *RuleTableManager) GetAllScopes(pt policy.Kind, scope, name, version string) ([]string, string, string) {
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

func (rt *RuleTableManager) CombineScopes(principalScopes, resourceScopes []string) []string {
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

func (rt *RuleTableManager) ScopedResourceExists(version, resource string, scopes []string) bool {
	if scopeMap, ok := rt.primaryIdx[version]; ok {
		for _, scope := range scopes {
			if roleMap, ok := scopeMap[scope]; ok && roleMap.Len() > 0 {
				for _, actionMap := range roleMap.GetAll() {
					for _, rules := range actionMap.GetAll() {
						for _, rule := range rules {
							if util.MatchesGlob(rule.Resource, resource) && rule.PolicyKind == policyv1.Kind_KIND_RESOURCE {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

func (rt *RuleTableManager) ScopedPrincipalExists(version string, scopes []string) bool {
	if scopeMap, ok := rt.primaryIdx[version]; ok {
		for _, scope := range scopes {
			if roleMap, ok := scopeMap[scope]; ok && roleMap.Len() > 0 {
				for _, actionMap := range roleMap.GetAll() {
					for _, rules := range actionMap.GetAll() {
						for _, rule := range rules {
							if rule.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}

func (rt *RuleTableManager) ScopedRoleExists(version, scope, role string) bool {
	if scopeMap, ok := rt.primaryIdx[version]; ok {
		if roleMap, ok := scopeMap[scope]; ok {
			if _, ok := roleMap.Get(role); ok {
				return true
			}
		}
	}

	return false
}

func (rt *RuleTableManager) GetRows(version, resource string, scopes, roles, actions []string) []*Row {
	res := []*Row{}

	processedActionSets := make(map[*util.GlobMap[[]*Row]]struct{})
	processedRuleSets := make(map[*[]*Row]struct{})
	if scopeSet, ok := rt.primaryIdx[version]; ok { //nolint:nestif
		for _, scope := range scopes {
			if roleSet, ok := scopeSet[scope]; ok {
				for _, role := range roles {
					roleFqn := namer.RolePolicyFQN(role, scope)
					for _, actionSet := range roleSet.GetMerged(role) {
						// wildcard roles lead to the same action set potentially being returned multiple times
						if _, ok := processedActionSets[actionSet]; ok {
							continue
						}
						processedActionSets[actionSet] = struct{}{}
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
											OriginFqn:      roleFqn,
											Resource:       resource,
											Role:           role,
											Effect:         effectv1.Effect_EFFECT_DENY,
											Scope:          scope,
											Version:        version,
											PolicyKind:     policyv1.Kind_KIND_RESOURCE,
											FromRolePolicy: true,
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
													EvaluationKey:    ar.EvaluationKey,
													PolicyKind:       policyv1.Kind_KIND_RESOURCE,
													FromRolePolicy:   true,
												},
											})
										}
									}
								}
							}
						}

						for _, action := range actions {
							for _, rules := range actionSet.GetMerged(action) {
								if _, ok := processedRuleSets[&rules]; ok {
									continue
								}
								processedRuleSets[&rules] = struct{}{}
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

func (rt *RuleTableManager) GetParentRoles(scope string, roles []string) []string {
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

func (rt *RuleTableManager) collectParentRoles(scope, role string, parentRoleSet, visited map[string]struct{}) {
	if _, seen := visited[role]; seen {
		return
	}
	visited[role] = struct{}{}

	if parentRoles, ok := rt.ScopeParentRoles[scope]; ok {
		if prs, ok := parentRoles.RoleParentRoles[role]; ok {
			for _, pr := range prs.Roles {
				parentRoleSet[pr] = struct{}{}
				rt.collectParentRoles(scope, pr, parentRoleSet, visited)
			}
		}
	}
}

func (rt *RuleTableManager) ScopeExists(pt policy.Kind, scope string) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var ok bool
	switch pt { //nolint:exhaustive
	case policy.PrincipalKind:
		_, ok = rt.principalScopeMap[scope]
	case policy.ResourceKind:
		_, ok = rt.resourceScopeMap[scope]
	}

	return ok
}

func (rt *RuleTableManager) GetScopeScopePermissions(scope string) policyv1.ScopePermissions {
	return rt.scopeScopePermissions[scope]
}

func (rt *RuleTableManager) GetSchema(fqn string) *policyv1.Schemas {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	modID := namer.GenModuleIDFromFQN(fqn)
	if s, ok := rt.Schemas[modID.RawValue()]; ok {
		return s
	}

	return nil
}

func (rt *RuleTableManager) GetMeta(fqn string) *runtimev1.RuleTableMetadata {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	modID := namer.GenModuleIDFromFQN(fqn)
	if s, ok := rt.Meta[modID.RawValue()]; ok {
		return s
	}

	return nil
}

func (rt *RuleTableManager) SubscriberID() string {
	return "engine.RuleTable"
}

func (rt *RuleTableManager) OnStorageEvent(events ...storage.Event) {
	for _, evt := range events {
		switch evt.Kind {
		case storage.EventReload, storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
			rt.log.Info("Reloading ruletable")
			// TODO(saml)
		default:
			rt.log.Debugw("Ignoring storage event", "event", evt)
		}
	}
}

// TODO(saml) rename to Check
func (rte *RuleTableManager) Evaluate(ctx context.Context, tctx tracer.Context, evalParams EvalParams, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	principalVersion := input.Principal.PolicyVersion
	if principalVersion == "" {
		principalVersion = evalParams.DefaultPolicyVersion
	}

	resourceVersion := input.Resource.PolicyVersion
	if resourceVersion == "" {
		resourceVersion = evalParams.DefaultPolicyVersion
	}

	trail := newAuditTrail(make(map[string]*policyv1.SourceAttributes))
	result := newEvalResult(input.Actions, trail)

	if !evalParams.LenientScopeSearch &&
		!rte.ScopeExists(policy.PrincipalKind, input.Principal.Scope) &&
		!rte.ScopeExists(policy.ResourceKind, input.Resource.Scope) {
		return result, nil
	}

	principalScopes, principalPolicyKey, _ := rte.GetAllScopes(policy.PrincipalKind, input.Principal.Scope, input.Principal.Id, principalVersion)
	resourceScopes, resourcePolicyKey, fqn := rte.GetAllScopes(policy.ResourceKind, input.Resource.Scope, input.Resource.Kind, resourceVersion)

	pctx := tctx.StartPolicy(fqn)

	// validate the input
	vr, err := rte.schemaMgr.ValidateCheckInput(ctx, rte.GetSchema(fqn), input)
	if err != nil {
		pctx.Failed(err, "Error during validation")

		return nil, fmt.Errorf("failed to validate input: %w", err)
	}

	if len(vr.Errors) > 0 {
		result.ValidationErrors = vr.Errors.SchemaErrors()

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
	evalCtx := NewEvalContext(evalParams, request)

	actionsToResolve := result.unresolvedActions()
	if len(actionsToResolve) == 0 {
		return result, nil
	}

	sanitizedResource := namer.SanitizedResource(input.Resource.Kind)
	scopedPrincipalExists := rte.ScopedPrincipalExists(principalVersion, principalScopes)
	scopedResourceExists := rte.ScopedResourceExists(resourceVersion, sanitizedResource, resourceScopes)
	if !scopedPrincipalExists && !scopedResourceExists {
		return result, nil
	}

	allRoles := rte.GetParentRoles(input.Resource.Scope, input.Principal.Roles)
	includingParentRoles := make(map[string]struct{})
	for _, r := range allRoles {
		includingParentRoles[r] = struct{}{}
	}

	candidateRows := rte.GetRows(resourceVersion, sanitizedResource, rte.CombineScopes(principalScopes, resourceScopes), allRoles, actionsToResolve)

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

				parentRoles := rte.GetParentRoles(input.Resource.Scope, []string{role})

			scopesLoop:
				for _, scope := range scopes {
					sctx := actx.StartScope(scope)

					// This is for backwards compatibility with effectiveDerivedRoles.
					// If we reach this point, we can assert that the given {origin policy + scope} combination has been evaluated
					// and therefore we build the effectiveDerivedRoles from those referenced in the policy.
					if pt == policyv1.Kind_KIND_RESOURCE { //nolint:nestif
						if _, ok := processedScopedDerivedRoles[scope]; !ok { //nolint:nestif
							effectiveDerivedRoles := make(internal.StringSet)
							if drs := rte.GetDerivedRoles(namer.ResourcePolicyFQN(input.Resource.Kind, resourceVersion, scope)); drs != nil {
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
										result.EffectiveDerivedRoles[name] = struct{}{}
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

						if m := rte.GetMeta(row.OriginFqn); m != nil && m.GetSourceAttributes() != nil {
							maps.Copy(result.AuditTrail.EffectivePolicies, m.GetSourceAttributes())
						}

						var constants map[string]any
						var variables map[string]any
						if row.Params != nil {
							constants = row.Params.Constants
							if c, ok := varCache[row.Params.Key]; ok {
								variables = c
							} else {
								var err error
								variables, err = evalCtx.evaluateCELProgramsOrVariables(ctx, pctx, constants, row.Params.CelPrograms, row.Params.Variables)
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
										derivedRoleVariables, err = evalCtx.evaluateCELProgramsOrVariables(ctx, drctx, derivedRoleConstants, row.DerivedRoleParams.CelPrograms, row.DerivedRoleParams.Variables)
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
								drSatisfied, err := evalCtx.SatisfiesCondition(ctx, tracer.Start(nil), row.DerivedRoleCondition, derivedRoleConstants, derivedRoleVariables)
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
									Src: namer.RuleFQN(rte.GetMeta(row.OriginFqn), row.Scope, row.Name),
									Val: evalCtx.evaluateProtobufValueCELExpr(ctx, outputExpr, row.Params.Constants, variables),
								}
								result.Outputs = append(result.Outputs, output)
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
									Src: namer.RuleFQN(rte.GetMeta(row.OriginFqn), row.Scope, row.Name),
									Val: evalCtx.evaluateProtobufValueCELExpr(ctx, row.EmitOutput.When.ConditionNotMet.Checked, row.Params.Constants, variables),
								}
								result.Outputs = append(result.Outputs, output)
								octx.ComputedOutput(output)
							}
							rulectx.Skipped(nil, conditionNotSatisfied)
						}
					}

					if _, hasAllow := roleEffectSet[effectv1.Effect_EFFECT_ALLOW]; hasAllow {
						switch rte.GetScopeScopePermissions(scope) { //nolint:exhaustive
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

type EvalParams struct {
	Globals              map[string]any
	NowFunc              conditions.NowFunc
	DefaultPolicyVersion string
	LenientScopeSearch   bool
}

type EffectInfo struct {
	Policy string
	Scope  string
	Effect effectv1.Effect
}

type PolicyEvalResult struct {
	Effects               map[string]EffectInfo
	EffectiveDerivedRoles map[string]struct{}
	toResolve             map[string]struct{}
	AuditTrail            *auditv1.AuditTrail
	ValidationErrors      []*schemav1.ValidationError
	Outputs               []*enginev1.OutputEntry
}

func newEvalResult(actions []string, auditTrail *auditv1.AuditTrail) *PolicyEvalResult {
	per := &PolicyEvalResult{
		Effects:               make(map[string]EffectInfo, len(actions)),
		EffectiveDerivedRoles: make(map[string]struct{}),
		toResolve:             make(map[string]struct{}, len(actions)),
		Outputs:               []*enginev1.OutputEntry{},
		AuditTrail:            auditTrail,
	}

	for _, a := range actions {
		per.toResolve[a] = struct{}{}
	}

	return per
}

func (er *PolicyEvalResult) unresolvedActions() []string {
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
func (er *PolicyEvalResult) setEffect(action string, effect EffectInfo) {
	delete(er.toResolve, action)

	if effect.Effect == effectv1.Effect_EFFECT_DENY {
		er.Effects[action] = effect
		return
	}

	current, ok := er.Effects[action]
	if !ok {
		er.Effects[action] = effect
		return
	}

	if current.Effect != effectv1.Effect_EFFECT_DENY {
		er.Effects[action] = effect
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
			Scope:         input.Principal.Scope,
		},
		Resource: &enginev1.Request_Resource{
			Kind:          input.Resource.Kind,
			Id:            input.Resource.Id,
			Attr:          input.Resource.Attr,
			PolicyVersion: input.Resource.PolicyVersion,
			Scope:         input.Resource.Scope,
		},
		AuxData: input.AuxData,
	}
}

type EvalContext struct {
	request               *enginev1.Request
	runtime               *enginev1.Runtime
	effectiveDerivedRoles internal.StringSet
	EvalParams
}

func NewEvalContext(ep EvalParams, request *enginev1.Request) *EvalContext {
	return &EvalContext{
		EvalParams: ep,
		request:    request,
	}
}

func (ec *EvalContext) withEffectiveDerivedRoles(effectiveDerivedRoles internal.StringSet) *EvalContext {
	return &EvalContext{
		EvalParams:            ec.EvalParams,
		request:               ec.request,
		effectiveDerivedRoles: effectiveDerivedRoles,
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

func (ec *EvalContext) evaluateCELProgramsOrVariables(ctx context.Context, tctx tracer.Context, constants map[string]any, celPrograms []*CelProgram, variables []*runtimev1.Variable) (map[string]any, error) {
	// if nowFunc is provided, we need to recompute the cel.Program to handle the custom time decorator, otherwise we can reuse the precomputed program
	// from build-time.
	if ec.NowFunc == nil {
		return ec.evaluatePrograms(constants, celPrograms)
	}

	return ec.evaluateVariables(ctx, tctx.StartVariables(), constants, variables)
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
		conditions.CELRequestIdent:    ec.request,
		conditions.CELResourceAbbrev:  ec.request.Resource,
		conditions.CELPrincipalAbbrev: ec.request.Principal,
		conditions.CELRuntimeIdent:    ec.lazyRuntime,
		conditions.CELConstantsIdent:  constants,
		conditions.CELConstantsAbbrev: constants,
		conditions.CELVariablesIdent:  variables,
		conditions.CELVariablesAbbrev: variables,
		conditions.CELGlobalsIdent:    ec.Globals,
		conditions.CELGlobalsAbbrev:   ec.Globals,
	}
}

func (ec *EvalContext) evaluatePrograms(constants map[string]any, celPrograms []*CelProgram) (map[string]any, error) {
	var errs error

	evalVars := make(map[string]any, len(celPrograms))
	for _, prg := range celPrograms {
		result, _, err := prg.Prog.Eval(ec.buildEvalVars(constants, evalVars))
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("error evaluating `%s`: %w", prg.Name, err))
			continue
		}

		evalVars[prg.Name] = result.Value()
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

	val, err := result.ConvertToNative(reflect.TypeOf(&structpb.Value{}))
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

	ast, err := celast.ToAST(expr)
	if err != nil {
		return nil, err
	}
	result, _, err := conditions.ContextEval(ctx, conditions.StdEnv, ast, ec.buildEvalVars(constants, variables), ec.NowFunc)
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
