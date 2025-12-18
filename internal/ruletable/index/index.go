// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"crypto/sha256"
	"maps"
	"slices"
	"sync/atomic"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	allowActionsIdxKey = "\x00_cerbos_reserved_allow_actions"

	versionKey      = "version"
	scopeKey        = "scope"
	roleGlobKey     = "roleGlob"
	actionGlobKey   = "actionGlob"
	resourceGlobKey = "resourceGlob"
)

var ignoredRuleTableProtoFields = map[string]struct{}{
	"cerbos.runtime.v1.RuleTableMetadata.source_attributes": {},
}

type Index interface {
	getLiteralMap(string) literalMap
	getGlobMap(string) globMap
	resolve(context.Context, []*Row) ([]*Row, error)
}

type batchWriter interface {
	setBatch(context.Context, map[string]*rowSet) error
}

type literalMap interface {
	batchWriter
	set(context.Context, string, *rowSet) error
	get(context.Context, ...string) (map[string]*rowSet, error)
	getAll(context.Context) (map[string]*rowSet, error)
	delete(context.Context, ...string) error
}

type globMap interface {
	batchWriter
	set(context.Context, string, *rowSet) error
	getWithLiteral(context.Context, ...string) (map[string]*rowSet, error)
	getMerged(context.Context, ...string) (map[string]*rowSet, error)
	getAll(context.Context) (map[string]*rowSet, error)
	delete(context.Context, ...string) error
}

type Row struct {
	*runtimev1.RuleTable_RuleRow
	Params                     *rowParams
	DerivedRoleParams          *rowParams
	sum                        string
	NoMatchForScopePermissions bool
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

type rowSet struct {
	m   map[string]*Row
	cow atomic.Bool // copy-on-write: if true, copy map before mutation
}

func newRowSet() *rowSet {
	return &rowSet{
		m: make(map[string]*Row),
	}
}

// ensureUnique copies the map if it's shared (cow flag is set).
func (s *rowSet) ensureUnique() {
	if s.cow.Load() {
		newM := make(map[string]*Row, len(s.m))
		maps.Copy(newM, s.m)
		s.m = newM
		s.cow.Store(false)
	}
}

func (l *rowSet) set(r *Row) {
	l.ensureUnique()
	if l.m == nil {
		l.m = make(map[string]*Row)
	}
	l.m[r.sum] = r
}

func (l *rowSet) has(sum string) bool {
	_, exists := l.m[sum]
	return exists
}

func (l *rowSet) len() int {
	return len(l.m)
}

func (l *rowSet) del(r *Row) {
	l.ensureUnique()
	delete(l.m, r.sum)
}

func (s *rowSet) unionWith(o *rowSet) *rowSet {
	if o == nil {
		return s
	}

	res := newRowSet()
	for _, r := range s.m {
		res.set(r)
	}
	for _, r := range o.m {
		res.set(r)
	}

	return res
}

// unionAll creates a new rowSet containing all rows from the given rowSets.
// More efficient than chained unionWith calls as it allocates only once.
func unionAll(sets ...*rowSet) *rowSet {
	// Calculate total capacity
	total := 0
	for _, s := range sets {
		if s != nil {
			total += len(s.m)
		}
	}

	res := &rowSet{m: make(map[string]*Row, total)}
	for _, s := range sets {
		if s != nil {
			for _, r := range s.m {
				res.m[r.sum] = r
			}
		}
	}
	return res
}

func (s *rowSet) intersectWith(o *rowSet) *rowSet {
	res := newRowSet()
	if o == nil {
		return res
	}

	for _, r := range s.m {
		if o.has(r.sum) {
			res.set(r)
		}
	}

	return res
}

func (s *rowSet) copy() *rowSet {
	// Mark original as shared
	s.cow.Store(true)
	// Create copy that shares the map
	c := &rowSet{m: s.m}
	c.cow.Store(true)
	return c
}

func (l *rowSet) rows() []*Row {
	res := make([]*Row, 0, len(l.m))
	for _, r := range l.m {
		res = append(res, r)
	}

	return res
}

func (rs *rowSet) resolve(ctx context.Context, idx Index) error {
	res, err := idx.resolve(ctx, rs.rows())
	if err != nil {
		return err
	}

	for _, row := range res {
		rs.set(row)
	}

	return nil
}

type Impl struct {
	idx          Index
	version      literalMap
	scope        literalMap
	roleGlob     globMap
	actionGlob   globMap
	resourceGlob globMap
}

func NewImpl(idx Index) *Impl {
	return &Impl{
		idx:          idx,
		version:      idx.getLiteralMap(versionKey),
		scope:        idx.getLiteralMap(scopeKey),
		roleGlob:     idx.getGlobMap(roleGlobKey),
		actionGlob:   idx.getGlobMap(actionGlobKey),
		resourceGlob: idx.getGlobMap(resourceGlobKey),
	}
}

func (m *Impl) IndexRules(ctx context.Context, rows []*Row) error {
	versions := make(map[string]*rowSet)
	scopes := make(map[string]*rowSet)
	roleGlobs := make(map[string]*rowSet)
	actionGlobs := make(map[string]*rowSet)
	resourceGlobs := make(map[string]*rowSet)

	addToSet := func(m map[string]*rowSet, key string, r *Row) {
		if _, ok := m[key]; !ok {
			m[key] = newRowSet()
		}
		m[key].set(r)
	}

	for _, r := range rows {
		h := sha256.New()
		r.HashPB(h, ignoredRuleTableProtoFields)
		r.sum = string(h.Sum(nil))

		addToSet(versions, r.Version, r)
		addToSet(scopes, r.Scope, r)
		addToSet(roleGlobs, r.Role, r)
		addToSet(resourceGlobs, r.Resource, r)

		action := r.GetAction()
		if len(r.GetAllowActions().GetActions()) > 0 {
			action = allowActionsIdxKey
		}
		addToSet(actionGlobs, action, r)
	}

	// TODO(saml) ideally, we'd batch _all_ writes within a single call, but this
	// is less intrusive and doesn't require a significant re-write (while still
	// seeing significant speed-ups).
	if err := m.updateIndex(ctx, m.version, m.version.get, versions); err != nil {
		return err
	}
	if err := m.updateIndex(ctx, m.scope, m.scope.get, scopes); err != nil {
		return err
	}
	if err := m.updateIndex(ctx, m.roleGlob, m.roleGlob.getWithLiteral, roleGlobs); err != nil {
		return err
	}
	if err := m.updateIndex(ctx, m.resourceGlob, m.resourceGlob.getWithLiteral, resourceGlobs); err != nil {
		return err
	}
	if err := m.updateIndex(ctx, m.actionGlob, m.actionGlob.getWithLiteral, actionGlobs); err != nil {
		return err
	}

	return nil
}

// updateIndex fetches existing rows for the keys in the batch, resolves them if necessary,
// merges them with the new batch, and writes the result back. This is only relevant
// for cases where the rule table is retrospectively updated by the manager (via mutable store
// events) after init.
func (m *Impl) updateIndex(ctx context.Context, bw batchWriter, getFn func(context.Context, ...string) (map[string]*rowSet, error), batch map[string]*rowSet) error {
	if len(batch) == 0 {
		return nil
	}

	keys := make([]string, 0, len(batch))
	for k := range batch {
		keys = append(keys, k)
	}

	existing, err := getFn(ctx, keys...)
	if err != nil {
		return err
	}

	for k, oldSet := range existing {
		if err := oldSet.resolve(ctx, m.idx); err != nil {
			return err
		}

		if newSet, ok := batch[k]; ok {
			batch[k] = oldSet.unionWith(newSet)
		}
	}

	return bw.setBatch(ctx, batch)
}

func (m *Impl) GetAllRows(ctx context.Context) ([]*Row, error) {
	versions, err := m.version.getAll(ctx)
	if err != nil {
		return nil, err
	}

	scopes, err := m.scope.getAll(ctx)
	if err != nil {
		return nil, err
	}

	roles, err := m.roleGlob.getAll(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := m.resourceGlob.getAll(ctx)
	if err != nil {
		return nil, err
	}

	actions, err := m.actionGlob.getAll(ctx)
	if err != nil {
		return nil, err
	}

	resSet := newRowSet()
	var res []*Row
	appendRows := func(rowSets map[string]*rowSet) {
		for _, rowSet := range rowSets {
			for _, row := range rowSet.rows() {
				if !resSet.has(row.sum) {
					resSet.set(row)
					res = append(res, row)
				}
			}
		}
	}

	appendRows(versions)
	appendRows(scopes)
	appendRows(roles)
	appendRows(resources)
	appendRows(actions)

	return res, nil
}

func (m *Impl) GetRows(ctx context.Context, version, resource string, scopes, roles, actions []string) ([]*Row, error) {
	// we need the determinism of a slice, so track results in that and use the resSet to prevent dupes
	resSet := newRowSet()
	res := []*Row{}

	sets, err := m.version.get(ctx, version)
	if err != nil {
		return nil, err
	}
	set, ok := sets[version]
	if !ok {
		return res, nil
	}

	resourceSets, err := m.resourceGlob.getMerged(ctx, resource)
	if err != nil {
		return nil, err
	}
	resourceSet, ok := resourceSets[resource]
	if !ok {
		return res, nil
	}
	set = set.intersectWith(resourceSet)

	scopeSets, err := m.scope.get(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	if len(scopeSets) == 0 {
		return res, nil
	}

	roleSets, err := m.roleGlob.getMerged(ctx, roles...)
	if err != nil {
		return nil, err
	}
	if len(roleSets) == 0 {
		return res, nil
	}

	literalActionSets, err := m.actionGlob.getWithLiteral(ctx, allowActionsIdxKey)
	if err != nil {
		return nil, err
	}

	actionSets, err := m.actionGlob.getMerged(ctx, actions...)
	if err != nil {
		return nil, err
	}

	if len(literalActionSets) == 0 && len(actionSets) == 0 {
		return res, nil
	}

	for _, scope := range scopes {
		scopeSet, ok := scopeSets[scope]
		if !ok {
			continue
		}
		scopeSet = scopeSet.intersectWith(set)

		for _, role := range roles {
			roleSet, ok := roleSets[role]
			if !ok {
				continue
			}
			roleSet = roleSet.intersectWith(scopeSet)

			roleFqn := namer.RolePolicyFQN(role, scope)

			if literalActionSet, ok := literalActionSets[allowActionsIdxKey]; ok { //nolint:nestif
				if ars := literalActionSet.intersectWith(roleSet).rows(); len(ars) > 0 {
					actionMatchedRows := util.NewGlobMap(make(map[string][]*Row))
					// retrieve actions mapped to all effectual rows
					resolved, err := m.idx.resolve(ctx, ars)
					if err != nil {
						return nil, err
					}
					for _, ar := range resolved {
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
			}

			for _, action := range actions {
				actionSet, ok := actionSets[action]
				if !ok {
					continue
				}
				for _, r := range actionSet.intersectWith(roleSet).rows() {
					if !resSet.has(r.sum) {
						resSet.set(r)
						res = append(res, r)
					}
				}
			}
		}
	}

	res, err = m.idx.resolve(ctx, res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (m *Impl) DeletePolicy(ctx context.Context, fqn string) error {
	if fqn == "" {
		return nil
	}

	allVersions, err := m.version.getAll(ctx)
	if err != nil {
		return err
	}
	for cat, rs := range allVersions {
		if err := rs.resolve(ctx, m.idx); err != nil {
			return err
		}
		initialLen := rs.len()
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
		if rs.len() == 0 {
			if err := m.version.delete(ctx, cat); err != nil {
				return err
			}
		} else if rs.len() != initialLen {
			if err := m.version.set(ctx, cat, rs); err != nil {
				return err
			}
		}
	}

	allScopes, err := m.scope.getAll(ctx)
	if err != nil {
		return err
	}
	for cat, rs := range allScopes {
		if err := rs.resolve(ctx, m.idx); err != nil {
			return err
		}
		initialLen := rs.len()
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
		if rs.len() == 0 {
			if err := m.scope.delete(ctx, cat); err != nil {
				return err
			}
		} else if rs.len() != initialLen {
			if err := m.scope.set(ctx, cat, rs); err != nil {
				return err
			}
		}
	}

	allRoleGlobs, err := m.roleGlob.getAll(ctx)
	if err != nil {
		return err
	}
	for cat, rs := range allRoleGlobs {
		if err := rs.resolve(ctx, m.idx); err != nil {
			return err
		}
		initialLen := rs.len()
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
		if rs.len() == 0 {
			if err := m.roleGlob.delete(ctx, cat); err != nil {
				return err
			}
		} else if rs.len() != initialLen {
			if err := m.roleGlob.set(ctx, cat, rs); err != nil {
				return err
			}
		}
	}

	allActionGlobs, err := m.actionGlob.getAll(ctx)
	if err != nil {
		return err
	}
	for cat, rs := range allActionGlobs {
		if err := rs.resolve(ctx, m.idx); err != nil {
			return err
		}
		initialLen := rs.len()
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
		if rs.len() == 0 {
			if err := m.actionGlob.delete(ctx, cat); err != nil {
				return err
			}
		} else if rs.len() != initialLen {
			if err := m.actionGlob.set(ctx, cat, rs); err != nil {
				return err
			}
		}
	}

	allResourceGlobs, err := m.resourceGlob.getAll(ctx)
	if err != nil {
		return err
	}
	for cat, rs := range allResourceGlobs {
		if err := rs.resolve(ctx, m.idx); err != nil {
			return err
		}
		initialLen := rs.len()
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
		if rs.len() == 0 {
			if err := m.resourceGlob.delete(ctx, cat); err != nil {
				return err
			}
		} else if rs.len() != initialLen {
			if err := m.resourceGlob.set(ctx, cat, rs); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Impl) GetScopes(ctx context.Context) ([]string, error) {
	scopeSets, err := m.scope.getAll(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]string, 0, len(scopeSets))
	for scope := range scopeSets {
		res = append(res, scope)
	}
	return res, nil
}

func (m *Impl) GetRoleGlobs(ctx context.Context) ([]string, error) {
	roleSets, err := m.roleGlob.getAll(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]string, 0, len(roleSets))
	for roleGlob := range roleSets {
		res = append(res, roleGlob)
	}
	return res, nil
}

func (m *Impl) ScopedRoleGlobExists(ctx context.Context, scope, role string) (bool, error) {
	roleGlobSets, err := m.roleGlob.getWithLiteral(ctx, role)
	if err != nil {
		return false, err
	}
	rs, ok := roleGlobSets[role]
	if !ok {
		return false, nil
	}

	scopeSets, err := m.scope.get(ctx, scope)
	if err != nil {
		return false, err
	}
	scopeSet, ok := scopeSets[scope]
	if !ok {
		return false, nil
	}
	return len(rs.intersectWith(scopeSet).m) > 0, nil
}

func (m *Impl) ScopedResourceExists(ctx context.Context, version, resource string, scopes []string) (bool, error) {
	versionSets, err := m.version.get(ctx, version)
	if err != nil {
		return false, err
	}
	rs, ok := versionSets[version]
	if !ok {
		return false, nil
	}

	scopesToUnion := make([]*rowSet, 0, len(scopes))
	for _, scope := range scopes {
		scopeRss, err := m.scope.get(ctx, scope)
		if err != nil {
			return false, err
		}
		if scopeRs, ok := scopeRss[scope]; ok {
			scopesToUnion = append(scopesToUnion, scopeRs)
		}
	}
	if len(scopesToUnion) == 0 {
		return false, nil
	}
	scopeSet := unionAll(scopesToUnion...)
	rs = rs.intersectWith(scopeSet)

	resourceSets, err := m.resourceGlob.getMerged(ctx, resource)
	if err != nil {
		return false, err
	}
	resourceSet, ok := resourceSets[resource]
	if !ok {
		return false, nil
	}
	rs = rs.intersectWith(resourceSet)

	if err := rs.resolve(ctx, m.idx); err != nil {
		return false, err
	}
	for _, rule := range rs.rows() {
		if rule.PolicyKind == policyv1.Kind_KIND_RESOURCE {
			return true, nil
		}
	}

	return false, nil
}

func (m *Impl) ScopedPrincipalExists(ctx context.Context, version string, scopes []string) (bool, error) {
	versionSets, err := m.version.get(ctx, version)
	if err != nil {
		return false, err
	}
	rs, ok := versionSets[version]
	if !ok {
		return false, nil
	}

	scopesToUnion := make([]*rowSet, 0, len(scopes))
	for _, scope := range scopes {
		scopeSets, err := m.scope.get(ctx, scope)
		if err != nil {
			return false, err
		}
		if ss, ok := scopeSets[scope]; ok {
			scopesToUnion = append(scopesToUnion, ss)
		}
	}
	if len(scopesToUnion) == 0 {
		return false, nil
	}
	scopeSet := unionAll(scopesToUnion...)
	rs = rs.intersectWith(scopeSet)

	if err := rs.resolve(ctx, m.idx); err != nil {
		return false, err
	}
	for _, rule := range rs.rows() {
		if rule.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
			return true, nil
		}
	}

	return false, nil
}

func (m *Impl) Reset() {
	m.version = m.idx.getLiteralMap(versionKey)
	m.scope = m.idx.getLiteralMap(scopeKey)
	m.roleGlob = m.idx.getGlobMap(roleGlobKey)
	m.actionGlob = m.idx.getGlobMap(actionGlobKey)
	m.resourceGlob = m.idx.getGlobMap(resourceGlobKey)
}

func GenerateRowParams(fqn string, orderedVariables []*runtimev1.Variable, constants map[string]*structpb.Value) (*rowParams, error) {
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
