// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"slices"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/cespare/xxhash/v2"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

// functionalRuleRowFields lists proto field names that affect evaluation outcome.
// Routing fields (scope, version, resource, role, action, principal) are excluded
// because they are handled by the bitmap index dimensions.
var functionalRuleRowFields = map[protoreflect.Name]struct{}{
	"condition": {}, "derived_role_condition": {},
	"effect": {}, "scope_permissions": {},
	"emit_output": {}, "params": {},
	"derived_role_params": {}, "policy_kind": {},
	"from_role_policy": {},
}

var nonFunctionalChecksumFields = func() map[string]struct{} {
	res := make(map[string]struct{})
	desc := (&runtimev1.RuleTable_RuleRow{}).ProtoReflect().Descriptor()
	fields := desc.Fields()
	for i := range fields.Len() {
		f := fields.Get(i)
		if _, ok := functionalRuleRowFields[f.Name()]; !ok {
			res[string(f.FullName())] = struct{}{}
		}
	}
	res["cerbos.runtime.v1.RuleTableMetadata.source_attributes"] = struct{}{}
	return res
}()

type CelProgram struct {
	Prog cel.Program
	Name string
	Expr string
}

type Option func(*Index)

// WithSourceRows retains the original proto row on each Binding, preventing
// GC of the proto rows after indexing.
func WithSourceRows() Option {
	return func(idx *Index) { idx.retainSourceRows = true }
}

type Index struct {
	bi               *bitmapIndex
	parentRoles      map[string]map[string][]string
	retainSourceRows bool
}

func New(opts ...Option) *Index {
	idx := &Index{bi: newBitmapIndex()}
	for _, o := range opts {
		o(idx)
	}
	return idx
}

func (m *Index) IndexRules(rules []*runtimev1.RuleTable_RuleRow) error {
	if len(rules) == 0 {
		return nil
	}

	if newBindings := len(rules) - len(m.bi.freeIDs); newBindings > 0 {
		m.bi.bindings = slices.Grow(m.bi.bindings, newBindings)
	}

	paramsCache := make(map[uint64]*RowParams)
	drParamsCache := make(map[uint64]*RowParams)

	for _, rule := range rules {
		var params, drParams *RowParams

		switch rule.PolicyKind { //nolint:exhaustive
		case policyv1.Kind_KIND_RESOURCE:
			if !rule.FromRolePolicy {
				p, err := getOrGenerateParams(paramsCache, rule.Params)
				if err != nil {
					return err
				}
				params = p
				if rule.OriginDerivedRole != "" {
					drp, err := getOrGenerateParams(drParamsCache, rule.DerivedRoleParams)
					if err != nil {
						return err
					}
					drParams = drp
				}
			}
		case policyv1.Kind_KIND_PRINCIPAL:
			p, err := getOrGenerateParams(paramsCache, rule.Params)
			if err != nil {
				return err
			}
			params = p
		}

		// hashpb does not include field tags, so Condition=X/DerivedRoleCondition=nil
		// hashes identically to Condition=nil/DerivedRoleCondition=X when X is the
		// same Condition content. Feed a discriminator byte into the hasher to break
		// the collision.
		// TODO(saml): addressing upstream in protoc-gen-go-hashpb, remove this when that lands.
		hasher := xxhash.New()
		rule.HashPB(hasher, nonFunctionalChecksumFields)
		var condDisc byte
		if rule.Condition != nil {
			condDisc |= 1
		}
		if rule.DerivedRoleCondition != nil {
			condDisc |= 2
		}
		_, _ = hasher.Write([]byte{condDisc})
		funcSum := hasher.Sum64()

		core, ok := m.bi.coresBySum[funcSum]
		if !ok {
			core = &FunctionalCore{
				Effect:               rule.Effect,
				Condition:            rule.Condition,
				DerivedRoleCondition: rule.DerivedRoleCondition,
				EmitOutput:           rule.EmitOutput,
				ScopePermissions:     rule.ScopePermissions,
				FromRolePolicy:       rule.FromRolePolicy,
				PolicyKind:           rule.PolicyKind,
				Params:               params,
				DerivedRoleParams:    drParams,
				origins:              make(map[string]struct{}),
				sum:                  funcSum,
			}
			m.bi.coresBySum[funcSum] = core
		}
		core.origins[rule.OriginFqn] = struct{}{}

		action := ""
		var allowActions map[string]struct{}
		switch v := rule.ActionSet.(type) {
		case *runtimev1.RuleTable_RuleRow_AllowActions_:
			allowActions = make(map[string]struct{}, len(v.AllowActions.GetActions()))
			for a := range v.AllowActions.GetActions() {
				allowActions[a] = struct{}{}
			}
		case *runtimev1.RuleTable_RuleRow_Action:
			action = v.Action
		}

		b := &Binding{
			Scope:             rule.Scope,
			Version:           rule.Version,
			Resource:          rule.Resource,
			Role:              rule.Role,
			Action:            action,
			Principal:         rule.Principal,
			OriginFqn:         rule.OriginFqn,
			OriginDerivedRole: rule.OriginDerivedRole,
			Name:              rule.Name,
			EvaluationKey:     rule.EvaluationKey,
			AllowActions:      allowActions,
			Core:              core,
		}
		if m.retainSourceRows {
			b.SourceRow = rule
		}

		m.bi.addBinding(b)
	}

	return nil
}

func (m *Index) GetAllRows() ([]*Binding, error) {
	res := make([]*Binding, 0, m.bi.universe.GetCardinality())
	for _, b := range m.bi.bindings {
		if b != nil {
			res = append(res, b)
		}
	}
	return res, nil
}

// Query returns bindings matching the given dimensions. Nil or zero-values mean
// "match all" for that dimension. Synthetic DENYs from role policy AllowActions
// are prepended when querying for a specific action with KIND_RESOURCE.
func (m *Index) Query(version, resource, scope, action string, roles []string, policyKind policyv1.Kind, principalID string, buf []*Binding) []*Binding {
	bi := m.bi

	if bi.universe.IsEmpty() {
		return buf
	}

	arena := newBitmapArena()
	defer arena.release()

	var scopeBM, versionBM, resourceBM, roleBM, policyKindBM, principalBM *roaring.Bitmap

	// scope is always filtered because "" is a valid literal scope (root scope).
	bm, ok := bi.scope.Get(scope)
	if !ok {
		return buf
	}
	scopeBM = bm

	if version != "" {
		bm, ok := bi.version.Get(version)
		if !ok {
			return buf
		}
		versionBM = bm
	}
	if resource != "" {
		bm := bi.resource.Query(arena, resource)
		if bm.IsEmpty() {
			return buf
		}
		resourceBM = bm
	}
	if len(roles) > 0 {
		roleBM = bi.role.QueryMultiple(arena, roles)
		if roleBM.IsEmpty() {
			return buf
		}
	}
	if policyKind != 0 {
		bm, ok := bi.policyKind.Get(policyKind)
		if !ok {
			return buf
		}
		policyKindBM = bm
	}
	if principalID != "" {
		bm, ok := bi.principal.Get(principalID)
		if !ok {
			return buf
		}
		principalBM = bm
	}

	dims := make([]*roaring.Bitmap, 0, 6) //nolint:mnd
	if versionBM != nil {
		dims = append(dims, versionBM)
	}
	if scopeBM != nil {
		dims = append(dims, scopeBM)
	}
	if resourceBM != nil {
		dims = append(dims, resourceBM)
	}
	if roleBM != nil {
		dims = append(dims, roleBM)
	}
	if policyKindBM != nil {
		dims = append(dims, policyKindBM)
	}
	if principalBM != nil {
		dims = append(dims, principalBM)
	}

	// baseBM = AND of all non-action dimensions.
	var baseBM *roaring.Bitmap
	switch len(dims) {
	case 0:
		baseBM = bi.universe
	case 1:
		baseBM = dims[0]
	case 2: //nolint:mnd
		baseBM = arena.and2(dims[0], dims[1])
	default:
		baseBM = arena.andInto(dims)
	}
	if baseBM.IsEmpty() {
		return buf
	}

	// resultBM = AND(baseBM, actionBM) for regular (non-AllowActions) bindings.
	resultBM := baseBM
	if action != "" {
		actionBM := bi.action.Query(arena, action)
		if !actionBM.IsEmpty() {
			resultBM = arena.and2(baseBM, actionBM)
		} else {
			resultBM = emptyBitmap
		}
	}

	// Role policy synthetic DENYs are prepended so the evaluator sees them
	// before regular ALLOWs, which is required for scope permission semantics.
	if action != "" && policyKind == policyv1.Kind_KIND_RESOURCE && !bi.allowActionsBitmap.IsEmpty() {
		buf = m.queryAllowActions(arena, bi, version, scope, action, resource, roles, versionBM, scopeBM, roleBM, resourceBM, buf)
	}

	// Regular bindings.
	if !resultBM.IsEmpty() {
		iter := resultBM.Iterator()
		for iter.HasNext() {
			id := iter.Next()
			if b := bi.getBinding(id); b != nil {
				buf = append(buf, b)
			}
		}
	}

	return buf
}

// queryAllowActions generates synthetic DENY bindings from role policy AllowActions.
func (m *Index) queryAllowActions(arena *bitmapArena, bi *bitmapIndex, version, scope, action, resource string, roles []string, versionBM, scopeBM, roleBM, resourceBM *roaring.Bitmap, res []*Binding,
) []*Binding {
	// find candidate role policy bindings.
	// we ignore `resource` because we need to know which roles have ANY role policies,
	// even if the `resource` doesn't match (which implies "DENY").
	// saml: benchmarks show a 3% speedup if we batch inputs to `FastAnd` below. In for a penny...
	candidateDims := make([]*roaring.Bitmap, 0, 4) //nolint:mnd
	if versionBM != nil {
		candidateDims = append(candidateDims, versionBM)
	}
	if scopeBM != nil {
		candidateDims = append(candidateDims, scopeBM)
	}
	if roleBM != nil {
		candidateDims = append(candidateDims, roleBM)
	}
	candidateDims = append(candidateDims, bi.allowActionsBitmap)

	var candidateBM *roaring.Bitmap
	if len(candidateDims) == 1 {
		candidateBM = candidateDims[0]
	} else {
		candidateBM = arena.andInto(candidateDims)
	}
	if candidateBM.IsEmpty() {
		return res
	}

	// now AND with the resource
	// (andInto returns a pooled copy so candidateBM isn't mutated).
	resourceMatchedBM := candidateBM
	if resourceBM != nil {
		resourceMatchedBM = arena.and2(candidateBM, resourceBM)
	}

	// we need two levels because we can't determine "does this role have a role policy"
	// from `resourceMatchedBM` alone; a role policy might exist but have no entry for
	// the requested resource, which is still an implicit DENY.
	// `candidateBM` tells us which roles have policies, `resourceMatchedBM` tells us
	// which of those actually cover the requested resource.
	rolesWithPolicy := make(map[string]struct{})
	iter := candidateBM.Iterator()
	for iter.HasNext() {
		b := bi.getBinding(iter.Next())
		if b == nil {
			continue
		}
		rolesWithPolicy[b.Role] = struct{}{}
	}

	// group resource-matched bindings by role.
	resourceMatchedByRole := make(map[string][]*Binding)
	if !resourceMatchedBM.IsEmpty() {
		rmIter := resourceMatchedBM.Iterator()
		for rmIter.HasNext() {
			b := bi.getBinding(rmIter.Next())
			if b == nil {
				continue
			}
			resourceMatchedByRole[b.Role] = append(resourceMatchedByRole[b.Role], b)
		}
	}

	// process each role in input order.
	var matched []*Binding
	for _, role := range roles {
		// no role policies exist for this role, skip it
		if _, ok := rolesWithPolicy[role]; !ok {
			continue
		}

		// find resource-matched bindings that cover the queried action.
		matched = matched[:0]
		for _, ab := range resourceMatchedByRole[role] {
			for a := range ab.AllowActions {
				if a == action || util.MatchesGlob(a, action) {
					matched = append(matched, ab)
					break
				}
			}
		}

		if len(matched) == 0 {
			// role policy exists but no AllowActions entry covers this resource+action == unconditional deny
			res = append(res, &Binding{
				Core: &FunctionalCore{
					Effect:         effectv1.Effect_EFFECT_DENY,
					PolicyKind:     policyv1.Kind_KIND_RESOURCE,
					FromRolePolicy: true,
				},
				Action:                     action,
				OriginFqn:                  namer.RolePolicyFQN(role, version, scope),
				Resource:                   resource,
				Role:                       role,
				Scope:                      scope,
				Version:                    version,
				NoMatchForScopePermissions: true,
			})
		} else {
			for _, ab := range matched {
				if ab.Core.Condition != nil {
					res = append(res, &Binding{
						Core: &FunctionalCore{
							Effect: effectv1.Effect_EFFECT_DENY,
							Condition: &runtimev1.Condition{
								Op: &runtimev1.Condition_None{
									None: &runtimev1.Condition_ExprList{
										Expr: []*runtimev1.Condition{ab.Core.Condition},
									},
								},
							},
							ScopePermissions: policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS,
							PolicyKind:       policyv1.Kind_KIND_RESOURCE,
							FromRolePolicy:   true,
						},
						Action:        action,
						OriginFqn:     ab.OriginFqn,
						Resource:      resource,
						Role:          ab.Role,
						Scope:         scope,
						Version:       version,
						EvaluationKey: ab.EvaluationKey,
					})
				}
			}
		}
	}

	return res
}

// QueryMulti returns bindings matching across multiple values per dimension.
// OR within each dimension, AND across dimensions.
// Unlike Query, AllowActions bindings are included directly (no synthetic DENY
// generation) because the caller handles action matching itself.
func (m *Index) QueryMulti(versions, resources, scopes, roles, actions []string) []*Binding {
	bi := m.bi

	if bi.universe.IsEmpty() {
		return nil
	}

	arena := newBitmapArena()
	defer arena.release()

	dims := make([]*roaring.Bitmap, 0, 4) //nolint:mnd

	if len(versions) > 0 {
		bm := bi.version.Query(arena, versions)
		if bm.IsEmpty() {
			return nil
		}
		dims = append(dims, bm)
	}
	if len(scopes) > 0 {
		bm := bi.scope.Query(arena, scopes)
		if bm.IsEmpty() {
			return nil
		}
		dims = append(dims, bm)
	}
	if len(resources) > 0 {
		bm := bi.resource.QueryMultiple(arena, resources)
		if bm.IsEmpty() {
			return nil
		}
		dims = append(dims, bm)
	}
	if len(roles) > 0 {
		bm := bi.role.QueryMultiple(arena, roles)
		if bm.IsEmpty() {
			return nil
		}
		dims = append(dims, bm)
	}

	var baseBM *roaring.Bitmap
	switch len(dims) {
	case 0:
		baseBM = bi.universe
	case 1:
		baseBM = dims[0]
	default:
		baseBM = arena.andInto(dims)
	}
	if baseBM.IsEmpty() {
		return nil
	}

	resultBM := m.applyActionFilter(arena, baseBM, actions)

	if resultBM.IsEmpty() {
		return nil
	}

	res := make([]*Binding, 0, resultBM.GetCardinality())
	iter := resultBM.Iterator()
	for iter.HasNext() {
		if b := bi.getBinding(iter.Next()); b != nil {
			res = append(res, b)
		}
	}
	return res
}

func (m *Index) applyActionFilter(arena *bitmapArena, baseBM *roaring.Bitmap, actions []string) *roaring.Bitmap {
	if len(actions) == 0 {
		return baseBM
	}

	bi := m.bi
	parts := make([]*roaring.Bitmap, 0, 2) //nolint:mnd

	actionBM := bi.action.QueryMultiple(arena, actions)
	if !actionBM.IsEmpty() {
		parts = append(parts, arena.and2(baseBM, actionBM))
	}
	if !bi.allowActionsBitmap.IsEmpty() {
		aaBM := arena.and2(baseBM, bi.allowActionsBitmap)
		if !aaBM.IsEmpty() {
			parts = append(parts, aaBM)
		}
	}

	switch len(parts) {
	case 0:
		return emptyBitmap
	case 1:
		return parts[0]
	default:
		return arena.orInto(parts)
	}
}

// AddParentRoles returns the given roles plus the union of all their parent roles across the provided scopes.
// When multiple scopes define parents for the same role, the results are merged rather than overwritten.
func (m *Index) AddParentRoles(scopes, roles []string) []string {
	if len(m.parentRoles) == 0 {
		return roles
	}

	merged := make(map[string][]string)
	for _, scope := range scopes {
		c, ok := m.parentRoles[scope]
		if !ok {
			continue
		}
		for role, parents := range c {
			merged[role] = append(merged[role], parents...)
		}
	}

	if len(merged) == 0 {
		return roles
	}

	result := make([]string, 0, len(roles)*2) //nolint:mnd
	result = append(result, roles...)
	for _, role := range roles {
		result = append(result, merged[role]...)
	}
	return result
}

func (m *Index) IndexParentRoles(scopeParentRoles map[string]*runtimev1.RuleTable_RoleParentRoles) error {
	m.parentRoles = compileParentRoleAncestors(scopeParentRoles)
	return nil
}

func compileParentRoleAncestors(scopeParentRoles map[string]*runtimev1.RuleTable_RoleParentRoles) map[string]map[string][]string {
	compiled := make(map[string]map[string][]string, len(scopeParentRoles))
	for scope, parentRoles := range scopeParentRoles {
		if parentRoles == nil {
			continue
		}

		compiled[scope] = make(map[string][]string, len(parentRoles.RoleParentRoles))
		for role := range parentRoles.RoleParentRoles {
			visited := make(map[string]struct{})
			roleParentsSet := make(map[string]struct{})
			collectParentRoles(scopeParentRoles, scope, role, roleParentsSet, visited)

			roleParents := make([]string, 0, len(roleParentsSet))
			for rp := range roleParentsSet {
				roleParents = append(roleParents, rp)
			}

			compiled[scope][role] = roleParents
		}
	}

	return compiled
}

func collectParentRoles(scopeParentRoles map[string]*runtimev1.RuleTable_RoleParentRoles, scope, role string, parentRoleSet, visited map[string]struct{}) {
	if _, seen := visited[role]; seen {
		return
	}
	visited[role] = struct{}{}

	if parentRoles, ok := scopeParentRoles[scope]; ok {
		if prs, ok := parentRoles.RoleParentRoles[role]; ok {
			for _, pr := range prs.Roles {
				parentRoleSet[pr] = struct{}{}
				collectParentRoles(scopeParentRoles, scope, pr, parentRoleSet, visited)
			}
		}
	}
}

func (m *Index) DeletePolicy(fqn string) error {
	if fqn == "" {
		return nil
	}

	fqnBM, ok := m.bi.fqnBindings.Get(fqn)
	if !ok {
		return nil
	}

	iter := fqnBM.Iterator()
	for iter.HasNext() {
		b := m.bi.getBinding(iter.Next())
		if b == nil {
			continue
		}

		delete(b.Core.origins, fqn)
		m.bi.removeBinding(b)

		if len(b.Core.origins) == 0 {
			delete(m.bi.coresBySum, b.Core.sum)
		}
	}

	m.bi.fqnBindings.Delete(fqn)

	return nil
}

func (m *Index) GetScopes() []string {
	return m.bi.scope.Keys()
}

func (m *Index) GetRoles() []string {
	return m.bi.role.GetAllKeys()
}

func (m *Index) GetVersions() []string {
	return m.bi.version.Keys()
}

func (m *Index) GetActions() []string {
	return m.bi.action.GetAllKeys()
}

func (m *Index) GetResources() []string {
	return m.bi.resource.GetAllKeys()
}

func (m *Index) ScopedResourceExists(version, resource string, scopes []string) (bool, error) {
	if len(scopes) == 0 {
		return false, nil
	}

	versionBM, ok := m.bi.version.Get(version)
	if !ok {
		return false, nil
	}

	arena := newBitmapArena()
	defer arena.release()

	scopeBM := m.bi.scope.Query(arena, scopes)
	if scopeBM.IsEmpty() {
		return false, nil
	}

	resourceBM := m.bi.resource.Query(arena, resource)
	if resourceBM.IsEmpty() {
		return false, nil
	}

	kindBM, ok := m.bi.policyKind.Get(policyv1.Kind_KIND_RESOURCE)
	if !ok {
		return false, nil
	}

	return intersectionNonEmpty(versionBM, scopeBM, resourceBM, kindBM), nil
}

func (m *Index) ScopedPrincipalExists(version string, scopes []string) (bool, error) {
	if len(scopes) == 0 {
		return false, nil
	}

	versionBM, ok := m.bi.version.Get(version)
	if !ok {
		return false, nil
	}

	arena := newBitmapArena()
	defer arena.release()

	scopeBM := m.bi.scope.Query(arena, scopes)
	if scopeBM.IsEmpty() {
		return false, nil
	}

	kindBM, ok := m.bi.policyKind.Get(policyv1.Kind_KIND_PRINCIPAL)
	if !ok {
		return false, nil
	}

	return intersectionNonEmpty(versionBM, scopeBM, kindBM), nil
}

func (m *Index) Reset() {
	m.bi = newBitmapIndex()
	m.parentRoles = nil
}

// getOrGenerateParams returns cached RowParams for the given proto content hash,
// compiling CEL programs on miss. Rows with identical params share the same pointer and Key.
func getOrGenerateParams(cache map[uint64]*RowParams, proto *runtimev1.RuleTable_RuleRow_Params) (*RowParams, error) {
	h := util.HashPB(proto, nil)
	if cached, ok := cache[h]; ok {
		return cached, nil
	}
	progs, err := getCelProgramsFromExpressions(proto.OrderedVariables)
	if err != nil {
		return nil, err
	}
	params := &RowParams{
		Key:         h,
		Variables:   proto.OrderedVariables,
		Constants:   (&structpb.Struct{Fields: proto.Constants}).AsMap(),
		CelPrograms: progs,
	}
	cache[h] = params
	return params, nil
}

func getCelProgramsFromExpressions(vars []*runtimev1.Variable) ([]*CelProgram, error) {
	progs := make([]*CelProgram, len(vars))

	for i, v := range vars {
		p, err := conditions.StdEnv.Program(
			cel.CheckedExprToAst(v.Expr.Checked),
			cel.CustomDecorator(conditions.CacheFriendlyTimeDecorator()),
		)
		if err != nil {
			return nil, err
		}

		progs[i] = &CelProgram{Name: v.Name, Prog: p, Expr: v.Expr.Original}
	}

	return progs, nil
}

// intersectionNonEmpty returns true if the intersection of all bitmaps is
// non-empty without allocating any new bitmaps. It iterates the smallest
// bitmap by cardinality and checks containment in the others.
func intersectionNonEmpty(bitmaps ...*roaring.Bitmap) bool {
	minIdx := 0
	minCard := bitmaps[0].GetCardinality()
	for i := 1; i < len(bitmaps); i++ {
		if c := bitmaps[i].GetCardinality(); c < minCard {
			minCard = c
			minIdx = i
		}
	}

	iter := bitmaps[minIdx].Iterator()
	for iter.HasNext() {
		v := iter.Next()
		inAll := true
		for i, bm := range bitmaps {
			if i != minIdx && !bm.Contains(v) {
				inAll = false
				break
			}
		}
		if inAll {
			return true
		}
	}
	return false
}
