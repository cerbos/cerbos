package index

import (
	"context"
	"crypto/sha256"
	"hash"
	"slices"

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
	getNamespace() string // TODO(saml) should I be using this?
	getLiteralMap(string) literalMap
	getGlobMap(string) globMap
}

type literalMap interface {
	set(context.Context, string, *rowSet) error
	get(context.Context, ...string) (map[string]*rowSet, error)
	getAll(context.Context) (map[string]*rowSet, error)
}

type globMap interface {
	set(context.Context, string, *rowSet) error
	getWithLiteral(context.Context, ...string) (map[string]*rowSet, error)
	getMerged(context.Context, ...string) (map[string]*rowSet, error)
	getAll(context.Context) (map[string]*rowSet, error)
}

type Row struct {
	*runtimev1.RuleTable_RuleRow
	sum                        [sha256.Size]byte
	Params                     *rowParams
	DerivedRoleParams          *rowParams
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
	m map[[sha256.Size]byte]*Row
}

func newRowSet() *rowSet {
	return &rowSet{
		m: make(map[[sha256.Size]byte]*Row),
	}
}

func (l *rowSet) set(r *Row) {
	if l.m == nil {
		l.m = make(map[[sha256.Size]byte]*Row)
	}
	l.m[r.sum] = r
}

func (l *rowSet) has(r *Row) bool {
	_, exists := l.m[r.sum]
	return exists
}

func (l *rowSet) del(r *Row) {
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

func (s *rowSet) intersectWith(o *rowSet) *rowSet {
	res := newRowSet()
	if o == nil {
		return res
	}

	for _, r := range s.m {
		if o.has(r) {
			res.set(r)
		}
	}

	return res
}

func (l *rowSet) rows() []*Row {
	res := make([]*Row, 0, len(l.m))
	for _, r := range l.m {
		res = append(res, r)
	}

	return res
}

type Impl struct {
	idx          Index
	rowHasher    hash.Hash
	version      literalMap
	scope        literalMap
	roleGlob     globMap
	actionGlob   globMap
	resourceGlob globMap
}

func NewImpl(idx Index) *Impl {
	return &Impl{
		idx:          idx,
		rowHasher:    sha256.New(),
		version:      idx.getLiteralMap(versionKey),
		scope:        idx.getLiteralMap(scopeKey),
		roleGlob:     idx.getGlobMap(roleGlobKey),
		actionGlob:   idx.getGlobMap(actionGlobKey),
		resourceGlob: idx.getGlobMap(resourceGlobKey),
	}
}

func (m *Impl) IndexRule(ctx context.Context, r *Row) error {
	defer m.rowHasher.Reset()
	r.HashPB(m.rowHasher, ignoredRuleTableProtoFields)
	m.rowHasher.Sum(r.sum[:0])

	versionRowSets, err := m.version.get(ctx, r.Version)
	if err != nil {
		return err
	}
	versionRowSet, ok := versionRowSets[r.Version]
	if !ok {
		versionRowSet = newRowSet()
	}
	versionRowSet.set(r)
	if err := m.version.set(ctx, r.Version, versionRowSet); err != nil {
		return err
	}

	scopeRowSets, err := m.scope.get(ctx, r.Scope)
	if err != nil {
		return err
	}
	scopeRowSet, ok := scopeRowSets[r.Scope]
	if !ok {
		scopeRowSet = newRowSet()
	}
	scopeRowSet.set(r)
	if err := m.scope.set(ctx, r.Scope, scopeRowSet); err != nil {
		return err
	}

	roleRowSets, err := m.roleGlob.getWithLiteral(ctx, r.Role)
	if err != nil {
		return err
	}
	roleRowSet, ok := roleRowSets[r.Role]
	if !ok {
		roleRowSet = newRowSet()
	}
	roleRowSet.set(r)
	if err := m.roleGlob.set(ctx, r.Role, roleRowSet); err != nil {
		return err
	}

	resourceRowSets, err := m.resourceGlob.getWithLiteral(ctx, r.Resource)
	if err != nil {
		return err
	}
	resourceRowSet, ok := resourceRowSets[r.Resource]
	if !ok {
		resourceRowSet = newRowSet()
	}
	resourceRowSet.set(r)
	if err := m.resourceGlob.set(ctx, r.Resource, resourceRowSet); err != nil {
		return err
	}

	action := r.GetAction()
	if len(r.GetAllowActions().GetActions()) > 0 {
		action = allowActionsIdxKey
	}
	actionRowSets, err := m.actionGlob.getWithLiteral(ctx, action)
	if err != nil {
		return err
	}
	actionRowSet, ok := actionRowSets[action]
	if !ok {
		actionRowSet = newRowSet()
	}
	actionRowSet.set(r)
	if err := m.actionGlob.set(ctx, action, actionRowSet); err != nil {
		return err
	}

	return nil
}

func (m *Impl) GetRows(ctx context.Context, version, resource string, scopes, roles, actions []string) ([]*Row, error) {
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

			literalActionSet, ok := literalActionSets[allowActionsIdxKey]
			if !ok {
				continue
			}
			if ars := literalActionSet.intersectWith(roleSet).rows(); len(ars) > 0 {
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
				actionSet, ok := actionSets[action]
				if !ok {
					continue
				}
				for _, r := range actionSet.intersectWith(roleSet).rows() {
					if !resSet.has(r) {
						resSet.set(r)
						res = append(res, r)
					}
				}
			}
		}
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
	for _, rs := range allVersions {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	allScopes, err := m.scope.getAll(ctx)
	if err != nil {
		return err
	}
	for _, rs := range allScopes {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	allRoleGlobs, err := m.roleGlob.getAll(ctx)
	if err != nil {
		return err
	}
	for _, rs := range allRoleGlobs {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	allActionGlobs, err := m.actionGlob.getAll(ctx)
	if err != nil {
		return err
	}
	for _, rs := range allActionGlobs {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
			}
		}
	}

	allResourceGlobs, err := m.resourceGlob.getAll(ctx)
	if err != nil {
		return err
	}
	for _, rs := range allResourceGlobs {
		for _, r := range rs.rows() {
			if r.OriginFqn == fqn {
				rs.del(r)
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

	scopeSet := newRowSet()
	for _, scope := range scopes {
		scopeRss, err := m.scope.get(ctx, scope)
		if err != nil {
			return false, err
		}
		scopeRs, ok := scopeRss[scope]
		if !ok {
			continue
		}
		scopeSet = scopeSet.unionWith(scopeRs)
	}
	if len(scopeSet.m) == 0 {
		return false, nil
	}
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

	for _, rule := range rs.m {
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

	scopeSet := newRowSet()
	for _, scope := range scopes {
		scopeSets, err := m.scope.get(ctx, scope)
		if err != nil {
			return false, err
		}
		ss, ok := scopeSets[scope]
		if !ok {
			continue
		}
		scopeSet = scopeSet.unionWith(ss)
	}
	if len(scopeSet.m) == 0 {
		return false, nil
	}
	rs = rs.intersectWith(scopeSet)

	for _, rule := range rs.m {
		if rule.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
			return true, nil
		}
	}

	return false, nil
}

func (m *Impl) Reset() {
	m.rowHasher = sha256.New()
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
