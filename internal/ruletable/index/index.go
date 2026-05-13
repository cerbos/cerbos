// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"slices"

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

type Index struct {
	bi          *bitmapIndex
	parentRoles map[string]map[string][]string
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

		m.bi.addBinding(b)
	}

	return nil
}

func (m *Index) GetAllRows() []*Binding {
	res := make([]*Binding, 0, m.bi.universe.GetCardinality())
	for _, b := range m.bi.bindings {
		if b != nil {
			res = append(res, b)
		}
	}
	return res
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

	var scopeBM, versionBM, resourceBM, roleBM, policyKindBM, principalBM *Bitmap

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

	dims := make([]*Bitmap, 0, 6) //nolint:mnd
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
	var baseBM *Bitmap
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
	if action != "" && resource != "" && policyKind == policyv1.Kind_KIND_RESOURCE && !bi.allowActionsBitmap.IsEmpty() {
		buf = m.appendRolePolicyDenies(arena, bi, []string{resource}, roles, []string{action}, versionBM, scopeBM, roleBM, buf)
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

// appendRolePolicyDenies appends synthetic DENY bindings for each (role,
// resource, action) triple where the role has a role policy matching
// versionBM ∩ scopeBM ∩ roleBM but doesn't explicitly allow that action
// for that resource.
//
// When roles is empty, iterates every role whose policy matches the
// non-resource dims (in binding-discovery order). Returns res unchanged if
// resources is empty.
//
// When targetActions is empty, the action set for synthesis is derived
// per-resource from the bindings (excluding principal-policy bindings) for
// that resource intersected with versionBM ∩ scopeBM. The role filter is
// deliberately ignored when deriving actions, so the action set reflects the
// resource's full surface, not just actions referenced by filtered roles.
func (m *Index) appendRolePolicyDenies(
	arena *bitmapArena, bi *bitmapIndex,
	resources, roles, targetActions []string,
	versionBM, scopeBM, roleBM *Bitmap,
	res []*Binding,
) []*Binding {
	// candidateBM deliberately omits resource so we can spot roles whose
	// policy exists but doesn't cover the requested resource.
	candidateDims := make([]*Bitmap, 0, 4) //nolint:mnd
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

	var candidateBM *Bitmap
	if len(candidateDims) == 1 {
		candidateBM = candidateDims[0]
	} else {
		candidateBM = arena.andInto(candidateDims)
	}
	if candidateBM.IsEmpty() {
		return res
	}

	// Retrieve one sample binding per role for version/scope
	rolePolicyRep := make(map[string]*Binding)
	var roleOrder []string
	policyIter := candidateBM.Iterator()
	for policyIter.HasNext() {
		b := bi.getBinding(policyIter.Next())
		if b == nil {
			continue
		}
		if _, ok := rolePolicyRep[b.Role]; !ok {
			roleOrder = append(roleOrder, b.Role)
			rolePolicyRep[b.Role] = b
		}
	}

	// Relevant in some (external) downstream consumers
	if len(roles) == 0 {
		roles = roleOrder
	}

	var matched []*Binding
	for _, resource := range resources {
		resBM := bi.resource.Query(arena, resource)
		resourceMatchedBM := emptyBitmap
		if !resBM.IsEmpty() {
			resourceMatchedBM = arena.and2(candidateBM, resBM)
		}

		resourceMatchedByRole := make(map[string][]*Binding)
		matchedIter := resourceMatchedBM.Iterator()
		for matchedIter.HasNext() {
			b := bi.getBinding(matchedIter.Next())
			if b == nil {
				continue
			}
			resourceMatchedByRole[b.Role] = append(resourceMatchedByRole[b.Role], b)
		}

		resourceActions := targetActions
		if len(resourceActions) == 0 {
			resourceActions = collectResourceActions(arena, bi, resBM, versionBM, scopeBM)
			if len(resourceActions) == 0 {
				continue
			}
		}

		for _, role := range roles {
			rep, ok := rolePolicyRep[role]
			if !ok {
				continue
			}
			roleBindings := resourceMatchedByRole[role]
			// role policy exists, but no resource bindings present
			if len(roleBindings) == 0 {
				for _, action := range resourceActions {
					res = append(res, newNoMatchRolePolicyDeny(role, rep.Version, rep.Scope, resource, action))
				}
				continue
			}

			for _, action := range resourceActions {
				matched = matched[:0]
				for _, rb := range roleBindings {
					for a := range rb.AllowActions {
						if a == action || util.MatchesGlob(a, action) {
							matched = append(matched, rb)
							break
						}
					}
				}

				// role policy exists with resource bindings, but action not specified
				if len(matched) == 0 {
					rep := roleBindings[0]
					res = append(res, newNoMatchRolePolicyDeny(role, rep.Version, rep.Scope, rep.Resource, action))
					continue
				}

				for _, mb := range matched {
					if mb.Core.Condition == nil {
						// Pure ACL allow: fall through. Role-policy bindings are
						// otherwise dropped here, so emit any output via a no-effect
						// binding.
						if mb.Core.EmitOutput != nil {
							res = append(res, &Binding{
								Core: &FunctionalCore{
									EmitOutput:     mb.Core.EmitOutput,
									PolicyKind:     policyv1.Kind_KIND_RESOURCE,
									FromRolePolicy: true,
									Params:         mb.Core.Params,
								},
								Action:        action,
								Name:          mb.Name,
								OriginFqn:     mb.OriginFqn,
								Resource:      mb.Resource,
								Role:          mb.Role,
								Scope:         mb.Scope,
								Version:       mb.Version,
								EvaluationKey: mb.EvaluationKey,
							})
						}
						continue
					}
					// Synthetic DENY for the negated condition. Outputs are swapped
					// because synthetic-activated == user-condition-not-met.
					var emitOutput *runtimev1.Output
					if mb.Core.EmitOutput != nil && mb.Core.EmitOutput.When != nil {
						emitOutput = &runtimev1.Output{
							When: &runtimev1.Output_When{
								RuleActivated:   mb.Core.EmitOutput.When.ConditionNotMet,
								ConditionNotMet: mb.Core.EmitOutput.When.RuleActivated,
							},
						}
					}
					res = append(res, &Binding{
						Core: &FunctionalCore{
							Effect: effectv1.Effect_EFFECT_DENY,
							Condition: &runtimev1.Condition{
								Op: &runtimev1.Condition_None{
									None: &runtimev1.Condition_ExprList{
										Expr: []*runtimev1.Condition{mb.Core.Condition},
									},
								},
							},
							EmitOutput:       emitOutput,
							ScopePermissions: policyv1.ScopePermissions_SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS,
							PolicyKind:       policyv1.Kind_KIND_RESOURCE,
							FromRolePolicy:   true,
							Params:           mb.Core.Params,
						},
						Action:        action,
						Name:          mb.Name,
						OriginFqn:     mb.OriginFqn,
						Resource:      mb.Resource,
						Role:          mb.Role,
						Scope:         mb.Scope,
						Version:       mb.Version,
						EvaluationKey: mb.EvaluationKey,
					})
				}
			}
		}
	}

	return res
}

// collectResourceActions returns the action names referenced by bindings on
// the given resource (intersected with version/scope). Principal-policy
// actions are excluded — they're principal-specific and shouldn't widen the
// resource's action set.
func collectResourceActions(arena *bitmapArena, bi *bitmapIndex, resBM, versionBM, scopeBM *Bitmap) []string {
	if resBM.IsEmpty() {
		return nil
	}

	dims := make([]*Bitmap, 0, 3) //nolint:mnd
	dims = append(dims, resBM)
	if versionBM != nil {
		dims = append(dims, versionBM)
	}
	if scopeBM != nil {
		dims = append(dims, scopeBM)
	}

	var bm *Bitmap
	if len(dims) == 1 {
		bm = dims[0]
	} else {
		bm = arena.andInto(dims)
	}
	if bm.IsEmpty() {
		return nil
	}

	actionSet := make(map[string]struct{})
	iter := bm.Iterator()
	for iter.HasNext() {
		b := bi.getBinding(iter.Next())
		if b == nil || b.Core.PolicyKind == policyv1.Kind_KIND_PRINCIPAL {
			continue
		}
		if b.Action != "" {
			actionSet[b.Action] = struct{}{}
		}
		for a := range b.AllowActions {
			actionSet[a] = struct{}{}
		}
	}

	actions := make([]string, 0, len(actionSet))
	for a := range actionSet {
		actions = append(actions, a)
	}
	return actions
}

func newNoMatchRolePolicyDeny(role, version, scope, resource, action string) *Binding {
	return &Binding{
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
	}
}

// QueryMulti returns bindings matching across multiple values per dimension
// (OR within each dimension, AND across dimensions). When withRolePolicyDenies
// is true, synthetic DENY bindings are appended for each (role, resource,
// action) triple where the role has a matching role policy that doesn't
// explicitly allow the action. An empty actions slice expands to every action
// in the index for synthesis.
func (m *Index) QueryMulti(versions, resources, scopes, roles, actions []string, withRolePolicyDenies bool) []*Binding {
	bi := m.bi
	if bi.universe.IsEmpty() {
		return nil
	}

	arena := newBitmapArena()
	defer arena.release()

	versionBM, scopeBM, ok := bi.versionScopeFilters(arena, versions, scopes)
	if !ok {
		return nil
	}

	var resourceBM, roleBM *Bitmap
	if len(roles) > 0 {
		roleBM = bi.role.QueryMultiple(arena, roles)
		if roleBM.IsEmpty() {
			return nil
		}
	}
	if len(resources) > 0 {
		// An empty resourceBM doesn't short-circuit: role-policy synthesis
		// still emits NoMatch denies when a role has a policy in the other
		// dimensions but no rows for the requested resource.
		resourceBM = bi.resource.QueryMultiple(arena, resources)
	}

	dims := make([]*Bitmap, 0, 4) //nolint:mnd
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

	var baseBM *Bitmap
	switch len(dims) {
	case 0:
		baseBM = bi.universe
	case 1:
		baseBM = dims[0]
	default:
		baseBM = arena.andInto(dims)
	}

	var res []*Binding
	if !baseBM.IsEmpty() {
		resultBM := m.applyActionFilter(arena, baseBM, actions)
		if !resultBM.IsEmpty() {
			res = make([]*Binding, 0, resultBM.GetCardinality())
			iter := resultBM.Iterator()
			for iter.HasNext() {
				if b := bi.getBinding(iter.Next()); b != nil {
					res = append(res, b)
				}
			}
		}
	}

	if !withRolePolicyDenies {
		return res
	}
	return m.appendRolePolicyDenies(arena, bi, resources, roles, actions, versionBM, scopeBM, roleBM, res)
}

func (m *Index) applyActionFilter(arena *bitmapArena, baseBM *Bitmap, actions []string) *Bitmap {
	if len(actions) == 0 {
		return baseBM
	}

	bi := m.bi
	parts := make([]*Bitmap, 0, 2) //nolint:mnd

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

	ids, ok := m.bi.fqnBindings.Get(fqn)
	if !ok {
		return nil
	}

	for _, id := range ids {
		b := m.bi.getBinding(id)
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

// Roles returns role keys matching the filters. An empty filter means
// match-all on that dimension. Glob keys (e.g. "manager:*") appear verbatim.
// Principal-policy rows are excluded.
func (m *Index) Roles(versions, scopes []string) []string {
	return m.bi.nonPrincipalDimensionKeys(m.bi.role, versions, scopes)
}

// Resources returns resource keys matching the filters.
// Matches `Roles` semantics above.
func (m *Index) Resources(versions, scopes []string) []string {
	return m.bi.nonPrincipalDimensionKeys(m.bi.resource, versions, scopes)
}

// ActionsForResource returns distinct actions on resource, filtered by
// versions and scopes. Empty filter = match-all; empty resource = nil.
//
// resource is matched as at evaluation: literal lookup plus any matching
// glob patterns. Principal-policy rows are excluded.
func (m *Index) ActionsForResource(resource string, versions, scopes []string) []string {
	if resource == "" {
		return nil
	}

	bi := m.bi
	arena := newBitmapArena()
	defer arena.release()

	versionBM, scopeBM, ok := bi.versionScopeFilters(arena, versions, scopes)
	if !ok {
		return nil
	}

	resBM := bi.resource.Query(arena, resource)
	return collectResourceActions(arena, bi, resBM, versionBM, scopeBM)
}

// nonPrincipalDimensionKeys returns keys of gd matching the filters,
// excluding principal-policy bindings. Returns nil if no KIND_RESOURCE
// bindings are indexed.
func (bi *bitmapIndex) nonPrincipalDimensionKeys(gd *globDimension, versions, scopes []string) []string {
	resourceKindBM, ok := bi.policyKind.Get(policyv1.Kind_KIND_RESOURCE)
	if !ok {
		return nil
	}

	arena := newBitmapArena()
	defer arena.release()

	versionBM, scopeBM, ok := bi.versionScopeFilters(arena, versions, scopes)
	if !ok {
		return nil
	}

	filters := make([]*Bitmap, 0, 3) //nolint:mnd
	filters = append(filters, resourceKindBM)
	if versionBM != nil {
		filters = append(filters, versionBM)
	}
	if scopeBM != nil {
		filters = append(filters, scopeBM)
	}

	filterBM := filters[0]
	if len(filters) > 1 {
		filterBM = arena.andInto(filters)
		if filterBM.IsEmpty() {
			return nil
		}
	}

	var keys []string
	gd.RangeBitmaps(func(k string, bm *Bitmap) {
		if intersectionNonEmpty(bm, filterBM) {
			keys = append(keys, k)
		}
	})
	return keys
}

// versionScopeFilters builds the filter bitmaps. ok=false means a non-empty
// input matched nothing. A nil bitmap means "no filter" for that dimension.
func (bi *bitmapIndex) versionScopeFilters(arena *bitmapArena, versions, scopes []string) (versionBM, scopeBM *Bitmap, ok bool) {
	if len(versions) > 0 {
		versionBM = bi.version.Query(arena, versions)
		if versionBM.IsEmpty() {
			return nil, nil, false
		}
	}
	if len(scopes) > 0 {
		scopeBM = bi.scope.Query(arena, scopes)
		if scopeBM.IsEmpty() {
			return nil, nil, false
		}
	}
	return versionBM, scopeBM, true
}

func (m *Index) ScopedResourceExists(version, resource string, scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}

	versionBM, ok := m.bi.version.Get(version)
	if !ok {
		return false
	}

	arena := newBitmapArena()
	defer arena.release()

	scopeBM := m.bi.scope.Query(arena, scopes)
	if scopeBM.IsEmpty() {
		return false
	}

	resourceBM := m.bi.resource.Query(arena, resource)
	if resourceBM.IsEmpty() {
		return false
	}

	kindBM, ok := m.bi.policyKind.Get(policyv1.Kind_KIND_RESOURCE)
	if !ok {
		return false
	}

	return intersectionNonEmpty(versionBM, scopeBM, resourceBM, kindBM)
}

func (m *Index) ScopedPrincipalExists(version string, scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}

	versionBM, ok := m.bi.version.Get(version)
	if !ok {
		return false
	}

	arena := newBitmapArena()
	defer arena.release()

	scopeBM := m.bi.scope.Query(arena, scopes)
	if scopeBM.IsEmpty() {
		return false
	}

	kindBM, ok := m.bi.policyKind.Get(policyv1.Kind_KIND_PRINCIPAL)
	if !ok {
		return false
	}

	return intersectionNonEmpty(versionBM, scopeBM, kindBM)
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
	progs, err := getCelProgramsFromExpressions(proto.GetOrderedVariables())
	if err != nil {
		return nil, err
	}
	params := &RowParams{
		Key:         h,
		Variables:   proto.GetOrderedVariables(),
		Constants:   (&structpb.Struct{Fields: proto.GetConstants()}).AsMap(),
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
