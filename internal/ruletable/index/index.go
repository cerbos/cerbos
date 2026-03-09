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
	"github.com/cerbos/cerbos/internal/ruletable/internal"
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

func (m *Index) GetRows(versions, resources, scopes, roles, actions []string, matchLiteral bool) ([]*Binding, error) {
	bi := m.bi

	if bi.universe.IsEmpty() {
		return nil, nil
	}

	// Build per-dimension bitmaps. Nil means "match all" (skip AND).
	var versionBM, scopeBM, resourceBM, roleBM, actionBM *roaring.Bitmap

	if len(versions) > 0 {
		versionBM = queryLiteralMap(bi.version, versions)
		if versionBM.IsEmpty() {
			return nil, nil
		}
	}
	if len(scopes) > 0 {
		scopeBM = queryLiteralMap(bi.scope, scopes)
		if scopeBM.IsEmpty() {
			return nil, nil
		}
	}
	if len(resources) > 0 {
		resourceBM = bi.resource.QueryMultiple(resources)
		if resourceBM.IsEmpty() {
			return nil, nil
		}
	}
	if len(roles) > 0 {
		roleBM = bi.role.QueryMultiple(roles)
		if roleBM.IsEmpty() {
			return nil, nil
		}
	}
	if len(actions) > 0 {
		actionBM = bi.action.QueryMultiple(actions)
	}

	// Collect non-nil base dimensions for FastAnd (avoids cloning the
	// large universe bitmap when at least two dimensions are provided).
	allBaseDims := []*roaring.Bitmap{versionBM, scopeBM, resourceBM, roleBM}
	baseDims := make([]*roaring.Bitmap, 0, len(allBaseDims))
	for _, bm := range allBaseDims {
		if bm != nil {
			baseDims = append(baseDims, bm)
		}
	}

	// baseBM is read-only: passed to FastAnd (which clones internally) or
	// iterated. No Clone needed.
	var baseBM *roaring.Bitmap
	switch len(baseDims) {
	case 0:
		baseBM = bi.universe
	case 1:
		baseBM = baseDims[0]
	default:
		baseBM = roaring.FastAnd(baseDims...)
	}
	if baseBM.IsEmpty() {
		return nil, nil
	}

	// Result = AND(base, action).
	resultBM := baseBM
	if actionBM != nil {
		resultBM = roaring.FastAnd(baseBM, actionBM)
	}

	var res []*Binding
	seen := make(map[uint32]struct{})

	addBinding := func(b *Binding) {
		if _, ok := seen[b.ID]; !ok {
			seen[b.ID] = struct{}{}
			res = append(res, b)
		}
	}

	// Handle AllowActions rows (BEFORE regular action rows so that
	// synthetic DENYs from role policies precede resource policy ALLOWs).
	//
	// Two-level check (matching old behaviour):
	//   Level 1: Does the role have ANY AllowActions binding for (role, scope, version)?
	//            This ignores resource — it detects that a role policy exists.
	//   Level 2: Which AllowActions bindings match the queried resource?
	//            If none match (but level 1 was true), generate blanket DENYs for all actions.
	if !bi.allowActionsBitmap.IsEmpty() { //nolint:nestif
		// Level 1: AllowActions bindings matching (version, scope, role) — no resource filter.
		allRoutingDims := []*roaring.Bitmap{versionBM, scopeBM, roleBM}
		routingDims := make([]*roaring.Bitmap, 0, len(allRoutingDims)+1)
		for _, bm := range allRoutingDims {
			if bm != nil {
				routingDims = append(routingDims, bm)
			}
		}
		routingDims = append(routingDims, bi.allowActionsBitmap)
		var roleScopeBM *roaring.Bitmap
		if len(routingDims) == 1 {
			roleScopeBM = routingDims[0]
		} else {
			roleScopeBM = roaring.FastAnd(routingDims...)
		}

		if !roleScopeBM.IsEmpty() {
			if len(actions) == 0 {
				actions = bi.action.GetAllKeys()
			}

			// Level 2: AllowActions bindings that also match the resource.
			allowBM := roaring.FastAnd(baseBM, bi.allowActionsBitmap)

			// Group by (role, scope, version) to process each combination independently.
			type routingKey struct{ role, scope, version string }

			type groupInfo struct {
				key      routingKey
				roleFqn  string
				bindings []*Binding
			}

			groupMap := make(map[routingKey]*groupInfo)

			// Identify all (role, scope, version) groups from the scope-level bitmap.
			rsIter := roleScopeBM.Iterator()
			for rsIter.HasNext() {
				id := rsIter.Next()
				b := bi.getBinding(id)
				if b == nil {
					continue
				}
				key := routingKey{b.Role, b.Scope, b.Version}
				if _, ok := groupMap[key]; !ok {
					groupMap[key] = &groupInfo{
						key:     key,
						roleFqn: namer.RolePolicyFQN(b.Role, b.Version, b.Scope),
					}
				}
			}

			// Attach resource-matched bindings to their groups.
			if !allowBM.IsEmpty() {
				aIter := allowBM.Iterator()
				for aIter.HasNext() {
					id := aIter.Next()
					ab := bi.getBinding(id)
					if ab == nil {
						continue
					}
					key := routingKey{ab.Role, ab.Scope, ab.Version}
					if g, ok := groupMap[key]; ok {
						g.bindings = append(g.bindings, ab)
					}
				}
			}

			// Build ordered group list matching input roles order (matching the
			// old nested-loop iteration: role → scope → version).
			var orderedGroups []*groupInfo
			for _, role := range roles {
				for _, scope := range scopes {
					for _, version := range versions {
						key := routingKey{role, scope, version}
						if g, ok := groupMap[key]; ok {
							orderedGroups = append(orderedGroups, g)
						}
					}
				}
			}

			actionMatchedBindings := internal.NewGlobMap(make(map[string][]*Binding))

			for _, group := range orderedGroups {
				key := group.key
				actionMatchedBindings.Clear()

				for _, ab := range group.bindings {
					for a := range ab.AllowActions {
						bs, _ := actionMatchedBindings.Get(a)
						bs = append(bs, ab)
						actionMatchedBindings.Set(a, bs)
					}
				}

				for _, action := range actions {
					var matched []*Binding
					for _, bs := range actionMatchedBindings.GetMerged(action) {
						matched = append(matched, bs...)
					}

					if matchLiteral {
						for _, b := range matched {
							addBinding(b)
						}
					} else {
						if len(matched) == 0 {
							for _, resource := range resources {
								res = append(res, &Binding{
									Core: &FunctionalCore{
										Effect:         effectv1.Effect_EFFECT_DENY,
										PolicyKind:     policyv1.Kind_KIND_RESOURCE,
										FromRolePolicy: true,
									},
									Action:                     action,
									OriginFqn:                  group.roleFqn,
									Resource:                   resource,
									Role:                       key.role,
									Scope:                      key.scope,
									Version:                    key.version,
									NoMatchForScopePermissions: true,
								})
							}
						} else {
							for _, ab := range matched {
								if ab.Core.Condition != nil {
									for _, resource := range resources {
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
											Scope:         key.scope,
											Version:       key.version,
											EvaluationKey: ab.EvaluationKey,
										})
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Collect regular action-matched bindings (after AllowActions so that
	// synthetic DENYs precede resource policy rows in the slice).
	iter := resultBM.Iterator()
	for iter.HasNext() {
		id := iter.Next()
		b := bi.getBinding(id)
		if b == nil {
			continue
		}
		addBinding(b)
	}

	return res, nil
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
