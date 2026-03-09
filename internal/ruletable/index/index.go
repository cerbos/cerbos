// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"encoding/binary"
	"slices"

	"github.com/RoaringBitmap/roaring/v2"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cespare/xxhash/v2"
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

var (
	nonFunctionalChecksumFields = buildNonFunctionalChecksumFields()
	hashSep                     = []byte{0}
)

func buildNonFunctionalChecksumFields() map[string]struct{} {
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
}

type CelProgram struct {
	Prog cel.Program
	Name string
	Expr string
}

type Index struct {
	bi          *bitmapIndex
	parentRoles map[string]map[string][]string
}

func New() *Index {
	return &Index{bi: newBitmapIndex()}
}

func (m *Index) IndexRules(rules []*runtimev1.RuleTable_RuleRow) error {
	if len(rules) == 0 {
		return nil
	}

	paramsCache := make(map[uint64]*RowParams)
	drParamsCache := make(map[uint64]*RowParams)

	for _, rule := range rules {
		var params, drParams *RowParams

		switch rule.PolicyKind { //nolint:exhaustive
		case policyv1.Kind_KIND_RESOURCE:
			if !rule.FromRolePolicy {
				p, err := getOrGenerateParams(paramsCache, rule.Params, rule.OriginFqn)
				if err != nil {
					return err
				}
				params = p
				if rule.OriginDerivedRole != "" {
					drp, err := getOrGenerateParams(drParamsCache, rule.DerivedRoleParams, namer.DerivedRolesFQN(rule.OriginDerivedRole))
					if err != nil {
						return err
					}
					drParams = drp
				}
			}
		case policyv1.Kind_KIND_PRINCIPAL:
			p, err := getOrGenerateParams(paramsCache, rule.Params, rule.OriginFqn)
			if err != nil {
				return err
			}
			params = p
		}

		funcSum := util.HashPB(rule, nonFunctionalChecksumFields)

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

		routingHash := computeRoutingHash(rule.Scope, rule.Version, rule.Resource,
			rule.Role, action, rule.Principal, allowActions, funcSum)

		if existingID, dup := m.bi.bindingDedup[routingHash]; dup {
			// Duplicate binding: merge origin on existing binding's core.
			if b := m.bi.getBinding(existingID); b != nil {
				addToFQNMap(m.bi.fqnBindings, rule.OriginFqn, existingID)
			}
			continue
		}

		// Allocate a new binding.
		id := m.bi.allocID()
		b := &Binding{
			ID:                id,
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

		m.bi.storeBinding(b)
		m.bi.addToDimensions(b)
		m.bi.bindingDedup[routingHash] = id
	}

	return nil
}

func computeRoutingHash(scope, version, resource, role, action, principal string,
	allowActions map[string]struct{}, funcSum uint64,
) uint64 {
	h := xxhash.New()
	_, _ = h.WriteString(scope)
	_, _ = h.Write(hashSep)
	_, _ = h.WriteString(version)
	_, _ = h.Write(hashSep)
	_, _ = h.WriteString(resource)
	_, _ = h.Write(hashSep)
	_, _ = h.WriteString(role)
	_, _ = h.Write(hashSep)
	_, _ = h.WriteString(action)
	_, _ = h.Write(hashSep)
	_, _ = h.WriteString(principal)
	_, _ = h.Write(hashSep)
	if allowActions != nil {
		sorted := make([]string, 0, len(allowActions))
		for a := range allowActions {
			sorted = append(sorted, a)
		}
		slices.Sort(sorted)
		for _, a := range sorted {
			_, _ = h.WriteString(a)
			_, _ = h.Write(hashSep)
		}
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], funcSum)
	_, _ = h.Write(buf[:])
	return h.Sum64()
}

func (m *Index) GetAllRows() ([]*Binding, error) {
	var res []*Binding
	for _, b := range m.bi.bindings {
		if b != nil {
			res = append(res, b)
		}
	}
	return res, nil
}

// Query returns bindings matching the given dimensions. Empty string / nil / zero
// means "match all" for that dimension. AllowActions synthetic DENYs are prepended
// when querying for a specific action with KIND_RESOURCE (or unspecified kind).
func (m *Index) Query(version, resource, scope, action string, roles []string, policyKind policyv1.Kind, principalID string) []*Binding {
	bi := m.bi

	if bi.universe.IsEmpty() {
		return nil
	}

	// Per-dimension bitmaps. Nil = match all (skip AND).
	// Scope is always filtered because "" is a valid literal scope (root scope).
	var versionBM, scopeBM, resourceBM, roleBM, policyKindBM, principalBM *roaring.Bitmap

	if version != "" {
		bm, ok := bi.version[version]
		if !ok {
			return nil
		}
		versionBM = bm
	}
	{
		bm, ok := bi.scope[scope]
		if !ok {
			return nil
		}
		scopeBM = bm
	}
	if resource != "" {
		bm := bi.resource.Query(resource)
		if bm.IsEmpty() {
			return nil
		}
		resourceBM = bm
	}
	if len(roles) > 0 {
		roleBM = bi.role.QueryMultiple(roles)
		if roleBM.IsEmpty() {
			return nil
		}
	}
	if policyKind != 0 {
		bm, ok := bi.policyKind[policyKind]
		if !ok {
			return nil
		}
		policyKindBM = bm
	}
	if principalID != "" {
		bm, ok := bi.principal[principalID]
		if !ok {
			return nil
		}
		principalBM = bm
	}

	// baseBM = AND of all non-action dimensions.
	nonNilDims := make([]*roaring.Bitmap, 0, 6) //nolint:mnd
	if versionBM != nil {
		nonNilDims = append(nonNilDims, versionBM)
	}
	if scopeBM != nil {
		nonNilDims = append(nonNilDims, scopeBM)
	}
	if resourceBM != nil {
		nonNilDims = append(nonNilDims, resourceBM)
	}
	if roleBM != nil {
		nonNilDims = append(nonNilDims, roleBM)
	}
	if policyKindBM != nil {
		nonNilDims = append(nonNilDims, policyKindBM)
	}
	if principalBM != nil {
		nonNilDims = append(nonNilDims, principalBM)
	}

	var baseBM *roaring.Bitmap
	switch len(nonNilDims) {
	case 0:
		baseBM = bi.universe
	case 1:
		baseBM = nonNilDims[0]
	default:
		baseBM = roaring.FastAnd(nonNilDims...)
	}
	if baseBM.IsEmpty() {
		return nil
	}

	// resultBM = AND(baseBM, actionBM) for regular (non-AllowActions) bindings.
	resultBM := baseBM
	if action != "" {
		actionBM := bi.action.Query(action)
		if !actionBM.IsEmpty() {
			resultBM = roaring.FastAnd(baseBM, actionBM)
		} else {
			resultBM = roaring.New()
		}
	}

	var res []*Binding

	// AllowActions synthetic DENYs (prepended before regular bindings).
	if action != "" && (policyKind == policyv1.Kind_KIND_RESOURCE || policyKind == 0) && !bi.allowActionsBitmap.IsEmpty() {
		res = m.queryAllowActions(bi, action, resource, roles, versionBM, scopeBM, roleBM, resourceBM, res)
	}

	// Regular bindings.
	if !resultBM.IsEmpty() {
		iter := resultBM.Iterator()
		for iter.HasNext() {
			id := iter.Next()
			if b := bi.getBinding(id); b != nil {
				res = append(res, b)
			}
		}
	}

	return res
}

// queryAllowActions generates synthetic DENY bindings from AllowActions (role policy)
// bindings. These DENYs are prepended before regular bindings so they take precedence.
func (m *Index) queryAllowActions(
	bi *bitmapIndex, action, resource string, roles []string,
	versionBM, scopeBM, roleBM, resourceBM *roaring.Bitmap,
	res []*Binding,
) []*Binding {
	// Level 1: AllowActions bindings matching (version, scope, roles) — no resource filter.
	level1Dims := make([]*roaring.Bitmap, 0, 4) //nolint:mnd
	if versionBM != nil {
		level1Dims = append(level1Dims, versionBM)
	}
	if scopeBM != nil {
		level1Dims = append(level1Dims, scopeBM)
	}
	if roleBM != nil {
		level1Dims = append(level1Dims, roleBM)
	}
	level1Dims = append(level1Dims, bi.allowActionsBitmap)

	var level1BM *roaring.Bitmap
	if len(level1Dims) == 1 {
		level1BM = level1Dims[0]
	} else {
		level1BM = roaring.FastAnd(level1Dims...)
	}
	if level1BM.IsEmpty() {
		return res
	}

	// Level 2: AllowActions bindings that also match the resource.
	level2BM := level1BM
	if resourceBM != nil {
		level2BM = roaring.FastAnd(level1BM, resourceBM)
	}

	// Group Level 1 bindings by role.
	type roleGroup struct {
		roleFqn  string
		scope    string
		version  string
		bindings []*Binding
	}
	groupMap := make(map[string]*roleGroup)

	iter := level1BM.Iterator()
	for iter.HasNext() {
		id := iter.Next()
		b := bi.getBinding(id)
		if b == nil {
			continue
		}
		if _, ok := groupMap[b.Role]; !ok {
			groupMap[b.Role] = &roleGroup{
				roleFqn: namer.RolePolicyFQN(b.Role, b.Version, b.Scope),
				scope:   b.Scope,
				version: b.Version,
			}
		}
	}

	// Attach Level 2 (resource-matched) bindings to their groups.
	if !level2BM.IsEmpty() {
		l2Iter := level2BM.Iterator()
		for l2Iter.HasNext() {
			id := l2Iter.Next()
			b := bi.getBinding(id)
			if b == nil {
				continue
			}
			if g, ok := groupMap[b.Role]; ok {
				g.bindings = append(g.bindings, b)
			}
		}
	}

	// Process each role in input order.
	for _, role := range roles {
		g, ok := groupMap[role]
		if !ok {
			continue
		}

		// Find AllowActions bindings from Level 2 that cover the queried action.
		var matched []*Binding
		for _, ab := range g.bindings {
			for a := range ab.AllowActions {
				if a == action || util.MatchesGlob(a, action) {
					matched = append(matched, ab)
					break
				}
			}
		}

		if len(matched) == 0 {
			res = append(res, &Binding{
				Core: &FunctionalCore{
					Effect:         effectv1.Effect_EFFECT_DENY,
					PolicyKind:     policyv1.Kind_KIND_RESOURCE,
					FromRolePolicy: true,
				},
				Action:                     action,
				OriginFqn:                  g.roleFqn,
				Resource:                   resource,
				Role:                       role,
				Scope:                      g.scope,
				Version:                    g.version,
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
						Scope:         g.scope,
						Version:       g.version,
						EvaluationKey: ab.EvaluationKey,
					})
				}
			}
		}
	}

	return res
}

// QueryMulti returns bindings matching across multiple values per dimension.
// Empty/nil slice = match all for that dimension.
// OR within each dimension, AND across dimensions.
// AllowActions bindings matching non-action dimensions are included (spitfire post-filters).
// No synthetic DENY generation.
func (m *Index) QueryMulti(versions, resources, scopes, roles, actions []string) []*Binding {
	bi := m.bi

	if bi.universe.IsEmpty() {
		return nil
	}

	dims := make([]*roaring.Bitmap, 0, 5) //nolint:mnd

	if len(versions) > 0 {
		bm := queryLiteralMap(bi.version, versions)
		if bm.IsEmpty() {
			return nil
		}
		dims = append(dims, bm)
	}
	if len(scopes) > 0 {
		bm := queryLiteralMap(bi.scope, scopes)
		if bm.IsEmpty() {
			return nil
		}
		dims = append(dims, bm)
	}
	if len(resources) > 0 {
		bm := bi.resource.QueryMultiple(resources)
		if bm.IsEmpty() {
			return nil
		}
		dims = append(dims, bm)
	}
	if len(roles) > 0 {
		bm := bi.role.QueryMultiple(roles)
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
		baseBM = roaring.FastAnd(dims...)
	}
	if baseBM.IsEmpty() {
		return nil
	}

	resultBM := m.applyActionFilter(baseBM, actions)

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

// applyActionFilter intersects baseBM with action bitmaps (OR of actions) and
// includes AllowActions bindings. If actions is empty, baseBM is returned as-is.
func (m *Index) applyActionFilter(baseBM *roaring.Bitmap, actions []string) *roaring.Bitmap {
	if len(actions) == 0 {
		return baseBM
	}

	bi := m.bi
	parts := make([]*roaring.Bitmap, 0, 2) //nolint:mnd

	actionBM := bi.action.QueryMultiple(actions)
	if !actionBM.IsEmpty() {
		parts = append(parts, roaring.FastAnd(baseBM, actionBM))
	}
	if !bi.allowActionsBitmap.IsEmpty() {
		aaBM := roaring.FastAnd(baseBM, bi.allowActionsBitmap)
		if !aaBM.IsEmpty() {
			parts = append(parts, aaBM)
		}
	}

	switch len(parts) {
	case 0:
		return roaring.New()
	case 1:
		return parts[0]
	default:
		return roaring.FastOr(parts...)
	}
}

// AddParentRoles returns the given roles plus the union of all their parent roles across the provided scopes.
func (m *Index) AddParentRoles(scopes, roles []string) ([]string, error) {
	if len(m.parentRoles) == 0 {
		return roles, nil
	}

	parentRoles := make([]string, len(roles))
	copy(parentRoles, roles)

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
		return parentRoles, nil
	}

	for _, role := range roles {
		if parents, ok := merged[role]; ok {
			parentRoles = append(parentRoles, parents...) //nolint:makezero
		}
	}

	return parentRoles, nil
}

// ParentRolesMap returns a pre-merged map of role → [role, parent1, parent2, ...] across the provided scopes.
// Each role's entry includes the role itself as the first element.
func (m *Index) ParentRolesMap(scopes []string) map[string][]string {
	if len(m.parentRoles) == 0 {
		return nil
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

	return merged
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

	fqnBM, ok := m.bi.fqnBindings[fqn]
	if !ok {
		return nil
	}

	// Collect IDs to remove (can't modify bitmap during iteration).
	idsToRemove := fqnBM.ToArray()

	for _, id := range idsToRemove {
		b := m.bi.getBinding(id)
		if b == nil {
			continue
		}

		// Remove this FQN from the core's origins.
		delete(b.Core.origins, fqn)

		// Check if any remaining origin still references this binding.
		referencedByOther := false
		for remainingFQN := range b.Core.origins {
			if bm, ok := m.bi.fqnBindings[remainingFQN]; ok && bm.Contains(id) {
				referencedByOther = true
				break
			}
		}

		if !referencedByOther {
			m.bi.removeFromDimensions(b)
			m.bi.freeID(id)

			routingHash := computeRoutingHash(b.Scope, b.Version, b.Resource,
				b.Role, b.Action, b.Principal, b.AllowActions, b.Core.sum)
			delete(m.bi.bindingDedup, routingHash)
		}

		if len(b.Core.origins) == 0 {
			delete(m.bi.coresBySum, b.Core.sum)
		}
	}

	delete(m.bi.fqnBindings, fqn)

	return nil
}

func (m *Index) GetScopes() ([]string, error) {
	res := make([]string, 0, len(m.bi.scope))
	for scope := range m.bi.scope {
		res = append(res, scope)
	}
	return res, nil
}

func (m *Index) GetRoleGlobs() ([]string, error) {
	return m.bi.role.GetAllKeys(), nil
}

func (m *Index) GetVersions() []string {
	res := make([]string, 0, len(m.bi.version))
	for v := range m.bi.version {
		res = append(res, v)
	}
	return res
}

func (m *Index) GetActions() []string {
	return m.bi.action.GetAllKeys()
}

func (m *Index) GetResources() []string {
	return m.bi.resource.GetAllKeys()
}

func (m *Index) ScopedRoleGlobExists(scope, role string) (bool, error) {
	roleBM := m.bi.role.Query(role)
	if roleBM.IsEmpty() {
		return false, nil
	}
	scopeBM, ok := m.bi.scope[scope]
	if !ok {
		return false, nil
	}
	return roleBM.Intersects(scopeBM), nil
}

func (m *Index) ScopedResourceExists(version, resource string, scopes []string) (bool, error) {
	if len(scopes) == 0 {
		return false, nil
	}

	versionBM, ok := m.bi.version[version]
	if !ok {
		return false, nil
	}

	scopeBM := queryLiteralMap(m.bi.scope, scopes)
	if scopeBM.IsEmpty() {
		return false, nil
	}

	resourceBM := m.bi.resource.Query(resource)
	if resourceBM.IsEmpty() {
		return false, nil
	}

	kindBM, ok := m.bi.policyKind[policyv1.Kind_KIND_RESOURCE]
	if !ok {
		return false, nil
	}

	return roaring.FastAnd(versionBM, scopeBM, resourceBM, kindBM).GetCardinality() > 0, nil
}

func (m *Index) ScopedPrincipalExists(version string, scopes []string) (bool, error) {
	if len(scopes) == 0 {
		return false, nil
	}

	versionBM, ok := m.bi.version[version]
	if !ok {
		return false, nil
	}

	scopeBM := queryLiteralMap(m.bi.scope, scopes)
	if scopeBM.IsEmpty() {
		return false, nil
	}

	kindBM, ok := m.bi.policyKind[policyv1.Kind_KIND_PRINCIPAL]
	if !ok {
		return false, nil
	}

	return roaring.FastAnd(versionBM, scopeBM, kindBM).GetCardinality() > 0, nil
}

func (m *Index) Reset() {
	m.bi = newBitmapIndex()
	m.parentRoles = nil
}

// getOrGenerateParams returns cached RowParams for the given proto hash, compiling CEL programs
// on miss. The returned Key reflects the fqn of whichever caller first populated the entry;
// callers must not rely on Key matching their fqn.
func getOrGenerateParams(cache map[uint64]*RowParams, proto *runtimev1.RuleTable_RuleRow_Params, fqn string) (*RowParams, error) {
	h := util.HashPB(proto, nil)
	if cached, ok := cache[h]; ok {
		return cached, nil
	}
	progs, err := getCelProgramsFromExpressions(proto.OrderedVariables)
	if err != nil {
		return nil, err
	}
	params := &RowParams{
		Key:         fqn,
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
			return progs, err
		}

		progs[i] = &CelProgram{Name: v.Name, Prog: p, Expr: v.Expr.Original}
	}

	return progs, nil
}
