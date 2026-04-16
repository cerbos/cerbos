// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"fmt"
	"slices"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// Marshal produces an immutable artefact: indexes reconstructed via Unmarshal are read-only snapshots and must not be passed to any mutating method on Index.
func (m *Index) Marshal() ([]byte, error) {
	bi := m.bi

	cores := make([]*FunctionalCore, 0, len(bi.coresBySum))
	for _, c := range bi.coresBySum {
		cores = append(cores, c)
	}

	coreIndex := make(map[*FunctionalCore]uint32, len(cores))
	pbCores := make([]*runtimev1.BitmapIndex_FunctionalCore, len(cores))
	for i, c := range cores {
		coreIndex[c] = uint32(i)
		pc, err := marshalCore(c)
		if err != nil {
			return nil, fmt.Errorf("marshaling core %d: %w", i, err)
		}
		pbCores[i] = pc
	}

	pbBindings := make([]*runtimev1.BitmapIndex_Binding, 0, len(bi.bindings)-len(bi.freeIDs))
	for _, b := range bi.bindings {
		if b == nil {
			continue
		}
		pbBindings = append(pbBindings, marshalBinding(b, coreIndex))
	}

	version, err := marshalEntries(bi.version.m)
	if err != nil {
		return nil, fmt.Errorf("marshaling version dimension: %w", err)
	}

	scope, err := marshalEntries(bi.scope.m)
	if err != nil {
		return nil, fmt.Errorf("marshaling scope dimension: %w", err)
	}

	policyKind := make(map[int32][]byte, len(bi.policyKind.m))
	for k, bm := range bi.policyKind.m {
		policyKind[int32(k)], err = bm.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshaling policy_kind dimension: %w", err)
		}
	}

	principal, err := marshalEntries(bi.principal.m)
	if err != nil {
		return nil, fmt.Errorf("marshaling principal dimension: %w", err)
	}

	role, err := marshalGlobDimension(bi.role)
	if err != nil {
		return nil, fmt.Errorf("marshaling role dimension: %w", err)
	}

	action, err := marshalGlobDimension(bi.action)
	if err != nil {
		return nil, fmt.Errorf("marshaling action dimension: %w", err)
	}

	resource, err := marshalGlobDimension(bi.resource)
	if err != nil {
		return nil, fmt.Errorf("marshaling resource dimension: %w", err)
	}

	universe, err := bi.universe.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling universe bitmap: %w", err)
	}

	allowActions, err := bi.allowActionsBitmap.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling allow_actions bitmap: %w", err)
	}

	msg := &runtimev1.BitmapIndex{
		Version:            version,
		Scope:              scope,
		Role:               role,
		Action:             action,
		Resource:           resource,
		PolicyKind:         policyKind,
		Principal:          principal,
		Universe:           universe,
		AllowActionsBitmap: allowActions,
		Bindings:           pbBindings,
		Cores:              pbCores,
		ParentRoles:        marshalParentRoles(m.parentRoles),
	}

	return msg.MarshalVT()
}

func marshalCore(c *FunctionalCore) (*runtimev1.BitmapIndex_FunctionalCore, error) {
	pc := &runtimev1.BitmapIndex_FunctionalCore{
		Effect:               c.Effect,
		Condition:            c.Condition,
		DerivedRoleCondition: c.DerivedRoleCondition,
		EmitOutput:           c.EmitOutput,
		ScopePermissions:     c.ScopePermissions,
		PolicyKind:           c.PolicyKind,
		FromRolePolicy:       c.FromRolePolicy,
	}

	if c.Params != nil {
		p, err := marshalRowParams(c.Params)
		if err != nil {
			return nil, err
		}
		pc.Params = p
	}
	if c.DerivedRoleParams != nil {
		p, err := marshalRowParams(c.DerivedRoleParams)
		if err != nil {
			return nil, err
		}
		pc.DerivedRoleParams = p
	}

	return pc, nil
}

func marshalRowParams(rp *RowParams) (*runtimev1.RuleTable_RuleRow_Params, error) {
	var constants map[string]*structpb.Value
	if len(rp.Constants) > 0 {
		s, err := structpb.NewStruct(rp.Constants)
		if err != nil {
			return nil, fmt.Errorf("converting constants to proto: %w", err)
		}
		constants = s.GetFields()
	}
	return &runtimev1.RuleTable_RuleRow_Params{
		OrderedVariables: rp.Variables,
		Constants:        constants,
	}, nil
}

func marshalBinding(b *Binding, coreIndex map[*FunctionalCore]uint32) *runtimev1.BitmapIndex_Binding {
	pb := &runtimev1.BitmapIndex_Binding{
		Id:                b.ID,
		CoreIndex:         coreIndex[b.Core],
		Role:              b.Role,
		Scope:             b.Scope,
		Version:           b.Version,
		Resource:          b.Resource,
		Principal:         b.Principal,
		OriginFqn:         b.OriginFqn,
		OriginDerivedRole: b.OriginDerivedRole,
		Name:              b.Name,
		EvaluationKey:     b.EvaluationKey,
	}

	if b.AllowActions != nil {
		actions := make([]string, 0, len(b.AllowActions))
		for a := range b.AllowActions {
			actions = append(actions, a)
		}
		pb.ActionSet = &runtimev1.BitmapIndex_Binding_AllowActions{
			AllowActions: &runtimev1.BitmapIndex_AllowActions{
				Actions: actions,
			},
		}
	} else if b.Action != "" {
		pb.ActionSet = &runtimev1.BitmapIndex_Binding_Action{
			Action: b.Action,
		}
	}

	return pb
}

func marshalGlobDimension(gd *globDimension) (*runtimev1.BitmapIndex_GlobDimension, error) {
	literals, err := marshalEntries(gd.literals)
	if err != nil {
		return nil, err
	}
	globs, err := marshalEntries(gd.globs)
	if err != nil {
		return nil, err
	}
	return &runtimev1.BitmapIndex_GlobDimension{
		Literals: literals,
		Globs:    globs,
	}, nil
}

func marshalEntries(m map[string]*Bitmap) ([]*runtimev1.BitmapIndex_Entry, error) {
	entries := make([]*runtimev1.BitmapIndex_Entry, 0, len(m))
	for k, bm := range m {
		b, err := bm.MarshalBinary()
		if err != nil {
			return nil, err
		}
		entries = append(entries, &runtimev1.BitmapIndex_Entry{
			Key:    k,
			Bitmap: b,
		})
	}
	return entries, nil
}

func marshalParentRoles(parentRoles map[string]map[string][]string) map[string]*runtimev1.BitmapIndex_RoleParents {
	if len(parentRoles) == 0 {
		return nil
	}
	out := make(map[string]*runtimev1.BitmapIndex_RoleParents, len(parentRoles))
	for scope, roleMap := range parentRoles {
		roles := make(map[string]*runtimev1.BitmapIndex_Parents, len(roleMap))
		for role, parents := range roleMap {
			roles[role] = &runtimev1.BitmapIndex_Parents{
				Parents: parents,
			}
		}
		out[scope] = &runtimev1.BitmapIndex_RoleParents{
			Roles: roles,
		}
	}
	return out
}

func Unmarshal(data []byte) (*Index, error) {
	msg := &runtimev1.BitmapIndex{}
	if err := msg.UnmarshalVT(data); err != nil {
		return nil, fmt.Errorf("unmarshaling proto: %w", err)
	}

	cores, err := unmarshalCores(msg.Cores)
	if err != nil {
		return nil, err
	}

	bi := newBitmapIndex()
	bi.bindings = unmarshalBindings(msg.Bindings, cores)

	bi.version, err = unmarshalEntries(msg.Version)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling version dimension: %w", err)
	}

	bi.scope, err = unmarshalEntries(msg.Scope)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling scope dimension: %w", err)
	}

	bi.policyKind.m = make(map[policyv1.Kind]*Bitmap, len(msg.PolicyKind))
	for k, data := range msg.PolicyKind {
		bi.policyKind.m[policyv1.Kind(k)], err = bitmapFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling policy_kind bitmap for kind %d: %w", k, err)
		}
	}

	bi.principal, err = unmarshalEntries(msg.Principal)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling principal dimension: %w", err)
	}

	bi.role, err = unmarshalGlobDimension(msg.Role)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling role dimension: %w", err)
	}

	bi.action, err = unmarshalGlobDimension(msg.Action)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling action dimension: %w", err)
	}

	bi.resource, err = unmarshalGlobDimension(msg.Resource)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling resource dimension: %w", err)
	}

	bi.universe, err = bitmapFromBytes(msg.Universe)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling universe bitmap: %w", err)
	}

	bi.allowActionsBitmap, err = bitmapFromBytes(msg.AllowActionsBitmap)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling allow_actions bitmap: %w", err)
	}

	return &Index{
		bi:          bi,
		parentRoles: unmarshalParentRoles(msg.ParentRoles),
	}, nil
}

func unmarshalCores(pbCores []*runtimev1.BitmapIndex_FunctionalCore) ([]*FunctionalCore, error) {
	cores := make([]*FunctionalCore, len(pbCores))
	paramsCache := make(map[uint64]*RowParams)
	drParamsCache := make(map[uint64]*RowParams)

	for i, pc := range pbCores {
		c := &FunctionalCore{
			Effect:               pc.Effect,
			Condition:            pc.Condition,
			DerivedRoleCondition: pc.DerivedRoleCondition,
			EmitOutput:           pc.EmitOutput,
			ScopePermissions:     pc.ScopePermissions,
			PolicyKind:           pc.PolicyKind,
			FromRolePolicy:       pc.FromRolePolicy,
		}

		if pc.Params != nil {
			p, err := getOrGenerateParams(paramsCache, pc.Params)
			if err != nil {
				return nil, err
			}
			c.Params = p
		}
		if pc.DerivedRoleParams != nil {
			p, err := getOrGenerateParams(drParamsCache, pc.DerivedRoleParams)
			if err != nil {
				return nil, err
			}
			c.DerivedRoleParams = p
		}

		cores[i] = c
	}

	return cores, nil
}

func unmarshalBindings(pbBindings []*runtimev1.BitmapIndex_Binding, cores []*FunctionalCore) []*Binding {
	if len(pbBindings) == 0 {
		return nil
	}

	// find the max ID to size the bindings slice.
	var maxID uint32
	for _, pb := range pbBindings {
		if pb.Id > maxID {
			maxID = pb.Id
		}
	}

	bindings := make([]*Binding, maxID+1)
	for _, pb := range pbBindings {
		b := &Binding{
			ID:                pb.Id,
			Core:              cores[pb.CoreIndex],
			Role:              pb.Role,
			Scope:             pb.Scope,
			Version:           pb.Version,
			Resource:          pb.Resource,
			Principal:         pb.Principal,
			OriginFqn:         pb.OriginFqn,
			OriginDerivedRole: pb.OriginDerivedRole,
			Name:              pb.Name,
			EvaluationKey:     pb.EvaluationKey,
		}

		switch v := pb.ActionSet.(type) {
		case *runtimev1.BitmapIndex_Binding_AllowActions:
			aa := make(map[string]struct{}, len(v.AllowActions.Actions))
			for _, a := range v.AllowActions.Actions {
				aa[a] = struct{}{}
			}
			b.AllowActions = aa
		case *runtimev1.BitmapIndex_Binding_Action:
			b.Action = v.Action
		}

		bindings[pb.Id] = b
	}

	return bindings
}

func unmarshalEntries(entries []*runtimev1.BitmapIndex_Entry) (dimension[string], error) {
	d := dimension[string]{m: make(map[string]*Bitmap, len(entries))}
	for _, e := range entries {
		bm, err := bitmapFromBytes(e.Bitmap)
		if err != nil {
			return d, fmt.Errorf("unmarshaling bitmap for key %q: %w", e.Key, err)
		}
		d.m[e.Key] = bm
	}
	return d, nil
}

func unmarshalGlobDimension(pb *runtimev1.BitmapIndex_GlobDimension) (*globDimension, error) {
	literals, err := unmarshalEntries(pb.Literals)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling literal dimension: %w", err)
	}

	gd := newGlobDimension()
	gd.literals = literals.m

	// can't use `unmarshalEntries` because each glob entry also
	// needs its pattern compiled into gd.compiled.
	for _, e := range pb.Globs {
		bm, err := bitmapFromBytes(e.Bitmap)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling glob bitmap for key %q: %w", e.Key, err)
		}
		gd.globs[e.Key] = bm
		g := util.GetOrCompileGlob(e.Key)
		if g == nil {
			return nil, fmt.Errorf("failed to compile glob pattern %q", e.Key)
		}
		gd.compiled[e.Key] = g
	}

	return gd, nil
}

func unmarshalParentRoles(pb map[string]*runtimev1.BitmapIndex_RoleParents) map[string]map[string][]string {
	if len(pb) == 0 {
		return nil
	}
	out := make(map[string]map[string][]string, len(pb))
	for scope, srp := range pb {
		roleMap := make(map[string][]string, len(srp.Roles))
		for role, rp := range srp.Roles {
			roleMap[role] = slices.Clone(rp.Parents)
		}
		out[scope] = roleMap
	}
	return out
}

func bitmapFromBytes(data []byte) (*Bitmap, error) {
	bm := NewBitmap()
	if len(data) == 0 {
		return bm, nil
	}
	if _, err := bm.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("reading bitmap: %w", err)
	}
	return bm, nil
}
