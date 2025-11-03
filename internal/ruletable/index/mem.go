package index

import (
	"crypto/sha256"
	"hash"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
)

var ignoredRuleTableProtoFields = map[string]struct{}{
	"cerbos.runtime.v1.RuleTableMetadata.source_attributes": {},
}

type rowSet struct {
	m map[[sha256.Size]byte]*Row
}

func newRowSet() *rowSet {
	return &rowSet{
		m: make(map[[sha256.Size]byte]*Row),
	}
}

func (s *rowSet) set(r *Row) {
	if s.m == nil {
		s.m = make(map[[sha256.Size]byte]*Row)
	}
	s.m[r.sum] = r
}

func (s *rowSet) has(r *Row) bool {
	_, exists := s.m[r.sum]
	return exists
}

func (s *rowSet) del(r *Row) {
	delete(s.m, r.sum)
}

func (s *rowSet) unionWith(o *rowSet) *rowSet {
	if o == nil {
		return s
	}

	for _, r := range o.m {
		s.set(r)
	}

	return s
}

func (s *rowSet) intersectWith(o *rowSet) *rowSet {
	if o == nil {
		return s
	}

	for _, r := range s.m {
		if !o.has(r) {
			delete(s.m, r.sum)
		}
	}

	return s
}

func (s *rowSet) rows() []*Row {
	res := make([]*Row, 0, len(s.m))
	for _, r := range s.m {
		res = append(res, r)
	}

	return res
}

type Mem struct {
	rowHasher    hash.Hash
	version      map[string]*rowSet
	scope        map[string]*rowSet
	roleGlob     *util.GlobMap[*rowSet]
	actionGlob   *util.GlobMap[*rowSet]
	resourceGlob *util.GlobMap[*rowSet]
}

func NewMem() *Mem {
	idx := &Mem{
		rowHasher:    sha256.New(),
		version:      make(map[string]*rowSet),
		scope:        make(map[string]*rowSet),
		roleGlob:     util.NewGlobMap(make(map[string]*rowSet)),
		actionGlob:   util.NewGlobMap(make(map[string]*rowSet)),
		resourceGlob: util.NewGlobMap(make(map[string]*rowSet)),
	}

	return idx
}

func (m *Mem) IndexRule(r *Row) {
	// TODO(saml) could actually just use a pointer as the map keys for in-mem maps
	defer m.rowHasher.Reset()
	r.HashPB(m.rowHasher, ignoredRuleTableProtoFields)
	m.rowHasher.Sum(r.sum[:0])

	versionRows, ok := m.version[r.Version]
	if !ok {
		versionRows = newRowSet()
		m.version[r.Version] = versionRows
	}
	versionRows.set(r)

	scopeRows, ok := m.scope[r.Scope]
	if !ok {
		scopeRows = newRowSet()
		m.scope[r.Scope] = scopeRows
	}
	scopeRows.set(r)

	roleRows, ok := m.roleGlob.GetWithLiteral(r.Role)
	if !ok {
		roleRows = newRowSet()
		m.roleGlob.Set(r.Role, roleRows)
	}
	roleRows.set(r)

	resourceRows, ok := m.resourceGlob.GetWithLiteral(r.Resource)
	if !ok {
		resourceRows = newRowSet()
		m.resourceGlob.Set(r.Resource, resourceRows)
	}
	resourceRows.set(r)

	action := r.GetAction()
	if len(r.GetAllowActions().GetActions()) > 0 {
		action = allowActionsIdxKey
	}
	actionRows, ok := m.actionGlob.GetWithLiteral(action)
	if !ok {
		actionRows = newRowSet()
		m.actionGlob.Set(action, actionRows)
	}
	actionRows.set(r)
}

func (m *Mem) GetRows(version, resource string, scopes, roles, actions []string) []*Row {
	resSet := newRowSet()
	res := []*Row{}

	set := newRowSet().unionWith(m.version[version])
	if len(set.m) == 0 {
		return res
	}

	resourceMap := m.resourceGlob.GetMerged(resource)
	resourceSet := newRowSet()
	for _, s := range resourceMap {
		resourceSet.unionWith(s)
	}
	set.intersectWith(resourceSet)

	for _, scope := range scopes {
		scopeSet := newRowSet().unionWith(m.scope[scope]).intersectWith(set)
		if len(scopeSet.m) == 0 {
			continue
		}

		for _, role := range roles {
			roleMap := m.roleGlob.GetMerged(role)
			roleSet := newRowSet()
			for _, s := range roleMap {
				roleSet.unionWith(s)
			}
			if len(roleSet.m) == 0 {
				continue
			}
			roleSet.intersectWith(scopeSet)

			roleFqn := namer.RolePolicyFQN(role, scope)

			literalActionSetOrig, _ := m.actionGlob.GetWithLiteral(allowActionsIdxKey)
			literalActionSet := newRowSet().unionWith(literalActionSetOrig).intersectWith(roleSet)
			if ars := literalActionSet.rows(); len(ars) > 0 {
				actionMatchedRows := util.NewGlobMap(make(map[string][]*Row))
				// retrieve actions mapped to all effectual rows
				for _, ar := range ars {
					for a := range ar.GetAllowActions().GetActions() {
						rows, _ := actionMatchedRows.Get(a)
						rows = append(rows, ar)
						actionMatchedRows.Set(a, rows)
					}
				}

				for _, action := range actions {
					matchedRows := []*Row{}
					for _, rows := range actionMatchedRows.GetMerged(action) {
						matchedRows = append(matchedRows, rows...)
					}
					if len(matchedRows) == 0 {
						// add a blanket DENY for non matching actions
						newRow := &Row{
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
						}
						resSet.set(newRow)
						res = append(res, newRow)
					} else {
						for _, ar := range matchedRows {
							// Don't bother adding a rule if there's no condition.
							// Otherwise, we invert the condition and set a DENY
							if ar.Condition != nil {
								newRow := &Row{
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
								}
								resSet.set(newRow)
								res = append(res, newRow)
							}
						}
					}
				}
			}

			for _, action := range actions {
				actionMap := m.actionGlob.GetMerged(action)
				actionSet := newRowSet()
				for _, s := range actionMap {
					actionSet.unionWith(s)
				}
				actionSet.intersectWith(roleSet)
				for _, r := range actionSet.rows() {
					if !resSet.has(r) {
						resSet.set(r)
						res = append(res, r)
					}
				}
			}
		}
	}

	return res
}

func (m *Mem) DeletePolicy(fqn string) {
	if fqn == "" {
		return
	}

	for _, rs := range m.version {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	for _, rs := range m.scope {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	for _, rs := range m.roleGlob.GetAll() {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	for _, rs := range m.actionGlob.GetAll() {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	for _, rs := range m.resourceGlob.GetAll() {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}
}

func (m *Mem) GetScopes() []string {
	res := make([]string, 0, len(m.scope))
	for scope := range m.scope {
		res = append(res, scope)
	}
	return res
}

func (m *Mem) GetRoleGlobs() []string {
	roles := m.roleGlob.GetAll()
	res := make([]string, 0, len(roles))
	for roleGlob := range roles {
		res = append(res, roleGlob)
	}
	return res
}

func (m *Mem) ScopedRoleGlobExists(scope, role string) bool {
	rsOrig, ok := m.roleGlob.GetWithLiteral(role)
	if !ok {
		return false
	}

	rs := newRowSet().unionWith(rsOrig).intersectWith(m.scope[scope])
	if len(rs.m) > 0 {
		return true
	}

	return false
}

func (m *Mem) ScopedResourceExists(version, resource string, scopes []string) bool {
	rs := newRowSet().unionWith(m.version[version])
	if len(rs.m) == 0 {
		return false
	}

	scopeSet := newRowSet()
	for _, scope := range scopes {
		scopeSet.unionWith(m.scope[scope])
	}
	if len(scopeSet.m) == 0 {
		return false
	}
	rs.intersectWith(scopeSet)

	resourceMap := m.resourceGlob.GetMerged(resource)
	resourceSet := newRowSet()
	for _, s := range resourceMap {
		resourceSet.unionWith(s)
	}
	rs.intersectWith(resourceSet)

	for _, rule := range rs.m {
		if rule.PolicyKind == policyv1.Kind_KIND_RESOURCE {
			return true
		}
	}

	return false
}

func (m *Mem) ScopedPrincipalExists(version string, scopes []string) bool {
	rs := newRowSet().unionWith(m.version[version])
	if len(rs.m) == 0 {
		return false
	}

	scopeSet := newRowSet()
	for _, scope := range scopes {
		scopeSet.unionWith(m.scope[scope])
	}
	if len(scopeSet.m) == 0 {
		return false
	}
	rs.intersectWith(scopeSet)

	for _, rule := range rs.m {
		if rule.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
			return true
		}
	}

	return false
}
