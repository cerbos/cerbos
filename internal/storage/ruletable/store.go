// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"fmt"
	"maps"
	"sync"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
)

type RuleTable struct {
	*runtimev1.RuleTable
	scopeMap            map[string]struct{}
	parentRoleAncestors map[string][]string
	mu                  sync.RWMutex
}

func NewRuleTable() *RuleTable {
	return &RuleTable{
		RuleTable: &runtimev1.RuleTable{
			ParentRoles: make(map[string]*runtimev1.RuleTable_ParentRoles),
			Schemas:     make(map[string]*policyv1.Schemas),
		},
		scopeMap:            make(map[string]struct{}),
		parentRoleAncestors: make(map[string][]string),
	}
}

func (rt *RuleTable) LoadPolicies(rps []*runtimev1.RunnablePolicySet) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for _, rp := range rps {
		rt.addPolicy(rp)
	}
}

func (rt *RuleTable) addPolicy(rps *runtimev1.RunnablePolicySet) {
	switch rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		rt.addResourcePolicy(rps.GetResourcePolicy())
	case *runtimev1.RunnablePolicySet_RolePolicy:
		rt.addRolePolicy(rps.GetRolePolicy())
	}
}

func (rt *RuleTable) addResourcePolicy(rrps *runtimev1.RunnableResourcePolicySet) {
	sanitizedResource := namer.SanitizedResource(rrps.Meta.Resource)

	meta := &runtimev1.RuleTable_Metadata{
		Fqn:              rrps.Meta.Fqn,
		Name:             &runtimev1.RuleTable_Metadata_Resource{Resource: sanitizedResource},
		Version:          rrps.Meta.Version,
		SourceAttributes: rrps.Meta.SourceAttributes,
		Annotations:      rrps.Meta.Annotations,
	}

	rt.Schemas[rrps.Meta.Fqn] = rrps.Schemas

	for _, p := range rrps.GetPolicies() {
		rt.scopeMap[p.Scope] = struct{}{}

		policyParameters := &runtimev1.RuleTable_Parameters{
			Origin:           namer.ResourcePolicyFQN(sanitizedResource, rrps.Meta.Version, p.Scope),
			OrderedVariables: p.OrderedVariables,
			Constants:        p.Constants,
		}

		scopePermissions := p.ScopePermissions
		if scopePermissions == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
			scopePermissions = policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
		}

		for _, rule := range p.Rules {
			emitOutput := rule.EmitOutput
			if emitOutput == nil && rule.Output != nil {
				emitOutput = &runtimev1.Output{
					When: &runtimev1.Output_When{
						RuleActivated: rule.Output,
					},
				}
			}

			ruleFqn := namer.RuleFQN(meta, p.Scope, rule.Name)
			evaluationKey := fmt.Sprintf("%s#%s", policyParameters.Origin, ruleFqn)
			for a := range rule.Actions {
				for r := range rule.Roles {
					rt.Rules = append(rt.Rules, &runtimev1.RuleTable_RuleRow{
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
						Parameters:       policyParameters,
						EvaluationKey:    evaluationKey,
						Meta:             meta,
					})
				}

				// merge derived roles as roles with added conditions
				for dr := range rule.DerivedRoles {
					if rdr, ok := p.DerivedRoles[dr]; ok {
						mergedVariables := make([]*runtimev1.Variable, len(p.OrderedVariables)+len(rdr.OrderedVariables))
						copy(mergedVariables, p.OrderedVariables)
						copy(mergedVariables[len(p.OrderedVariables):], rdr.OrderedVariables)

						mergedConstants := maps.Clone(p.Constants)
						for k, c := range rdr.Constants {
							mergedConstants[k] = c
						}

						mergedParameters := &runtimev1.RuleTable_Parameters{
							Origin:           fmt.Sprintf("%s:%s", policyParameters.Origin, namer.DerivedRolesFQN(rdr.Name)),
							OrderedVariables: mergedVariables,
							Constants:        mergedConstants,
						}

						cond := rule.Condition
						if rdr.Condition != nil {
							if cond == nil {
								cond = rdr.Condition
							} else {
								cond = &runtimev1.Condition{
									Op: &runtimev1.Condition_All{
										All: &runtimev1.Condition_ExprList{
											Expr: []*runtimev1.Condition{cond, rdr.Condition},
										},
									},
								}
							}
						}

						evaluationKey := fmt.Sprintf("%s#%s", mergedParameters.Origin, ruleFqn)
						for pr := range rdr.ParentRoles {
							rt.Rules = append(rt.Rules, &runtimev1.RuleTable_RuleRow{
								Resource:          sanitizedResource,
								Role:              pr,
								Action:            a,
								Condition:         cond,
								Effect:            rule.Effect,
								Scope:             p.Scope,
								ScopePermissions:  scopePermissions,
								Version:           rrps.Meta.Version,
								OriginDerivedRole: dr,
								EmitOutput:        emitOutput,
								Name:              rule.Name,
								Parameters:        mergedParameters,
								EvaluationKey:     evaluationKey,
								Meta:              meta,
							})
						}
					}
				}
			}
		}
	}
}

func (rt *RuleTable) addRolePolicy(p *runtimev1.RunnableRolePolicySet) {
	rt.scopeMap[p.Scope] = struct{}{}

	version := "default"
	meta := &runtimev1.RuleTable_Metadata{
		Fqn:              p.GetMeta().Fqn,
		Name:             &runtimev1.RuleTable_Metadata_Role{Role: p.Role},
		Version:          version,
		SourceAttributes: p.GetMeta().SourceAttributes,
		Annotations:      p.GetMeta().Annotations,
	}
	for resource, rl := range p.Resources {
		for idx, rule := range rl.Rules {
			evaluationKey := fmt.Sprintf("%s#%s", namer.PolicyKeyFromFQN(namer.RolePolicyFQN(p.Role, p.Scope)), fmt.Sprintf("%s_rule-%03d", p.Role, idx))
			for a := range rule.Actions {
				rt.Rules = append(rt.Rules, &runtimev1.RuleTable_RuleRow{
					Role:             p.Role,
					Resource:         resource,
					Action:           a,
					Condition:        rule.Condition,
					Effect:           effectv1.Effect_EFFECT_ALLOW,
					Scope:            p.Scope,
					ScopePermissions: p.ScopePermissions,
					Version:          version,
					EvaluationKey:    evaluationKey,
					Meta:             meta,
				})
			}
		}
	}

	rt.ParentRoles[p.Role] = &runtimev1.RuleTable_ParentRoles{
		ParentRoles: p.ParentRoles,
	}
}

func (rt *RuleTable) ScanRows(version, resource string, scopes, roles, actions []string) *RuleSet {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	res := &RuleSet{
		scopeIndex:            make(map[string][]*runtimev1.RuleTable_RuleRow),
		scopeScopePermissions: make(map[string]policyv1.ScopePermissions),
	}

	scopeSet := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = struct{}{}
	}

	parentRoles := rt.getParentRoles(roles)

	for _, row := range rt.Rules {
		if version != row.Version {
			continue
		}

		if _, ok := scopeSet[row.Scope]; !ok {
			continue
		}

		if !util.MatchesGlob(row.Resource, resource) {
			continue
		}

		if len(actions) > 0 {
			if len(util.FilterGlob(row.Action, actions)) == 0 {
				continue
			}
		}

		if len(roles) > 0 {
			if len(util.FilterGlob(row.Role, roles)) == 0 {
				// if the row matched on an assumed parent role, update the role in the row to an arbitrary base role
				// so that we don't need to retrieve parent roles each time we query on the same set of data.
				if len(util.FilterGlob(row.Role, parentRoles)) > 0 {
					row.Role = roles[0]
				} else {
					continue
				}
			}
		}

		res.addMatchingRow(row)
	}

	return res
}

func (rt *RuleTable) getParentRoles(roles []string) []string {
	// recursively collect all parent roles, caching the flat list on the very first traversal for
	// each role within the ruletable
	parentRoles := []string{}
	for _, role := range roles {
		var roleParents []string
		if c, ok := rt.parentRoleAncestors[role]; ok {
			roleParents = c
		} else {
			visited := make(map[string]struct{})
			roleParents = rt.collectParentRoles(role, roleParents, visited)
			rt.parentRoleAncestors[role] = roleParents
		}
		parentRoles = append(parentRoles, roleParents...)
	}
	return parentRoles
}

func (rt *RuleTable) collectParentRoles(role string, parentRoleSet []string, visited map[string]struct{}) []string {
	if _, seen := visited[role]; seen {
		return parentRoleSet
	}
	visited[role] = struct{}{}

	if prs, ok := rt.ParentRoles[role]; ok {
		for _, pr := range prs.ParentRoles {
			parentRoleSet = append(parentRoleSet, pr)
			parentRoleSet = append(parentRoleSet, rt.collectParentRoles(pr, parentRoleSet, visited)...)
		}
	}
	return parentRoleSet
}

func (rt *RuleTable) ScopeExists(scope string) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	_, ok := rt.scopeMap[scope]
	return ok
}

func (rt *RuleTable) GetSchema(fqn string) *policyv1.Schemas {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	if s, ok := rt.Schemas[fqn]; ok {
		return s
	}

	return nil
}

func (rt *RuleTable) Filter(rrs *RuleSet, scopes, roles, actions []string) *RuleSet {
	res := &RuleSet{
		scopeIndex:            make(map[string][]*runtimev1.RuleTable_RuleRow),
		scopeScopePermissions: make(map[string]policyv1.ScopePermissions),
	}

	parentRoles := rt.getParentRoles(roles)

	for _, s := range scopes {
		if sMap, ok := rrs.scopeIndex[s]; ok {
			for _, row := range sMap {
				if len(util.FilterGlob(row.Action, actions)) > 0 {
					if len(util.FilterGlob(row.Role, roles)) > 0 {
						res.addMatchingRow(row)
					} else if len(util.FilterGlob(row.Role, parentRoles)) > 0 {
						// TODO(saml) dedup from Scan method
						row.Role = roles[0]
						res.addMatchingRow(row)
					}
				}
			}
		}
	}

	return res
}

type RuleSet struct {
	rows                  []*runtimev1.RuleTable_RuleRow
	scopeIndex            map[string][]*runtimev1.RuleTable_RuleRow
	scopeScopePermissions map[string]policyv1.ScopePermissions
}

func (rrs *RuleSet) addMatchingRow(row *runtimev1.RuleTable_RuleRow) {
	rrs.rows = append(rrs.rows, row)

	rrs.scopeIndex[row.Scope] = append(rrs.scopeIndex[row.Scope], row)

	if _, ok := rrs.scopeScopePermissions[row.Scope]; !ok {
		rrs.scopeScopePermissions[row.Scope] = row.ScopePermissions
	}
}

func (rrs *RuleSet) GetScopeScopePermissions(scope string) policyv1.ScopePermissions {
	return rrs.scopeScopePermissions[scope]
}

func (rrs *RuleSet) GetRows() []*runtimev1.RuleTable_RuleRow {
	return rrs.rows
}
