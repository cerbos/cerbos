// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"unique"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
)

// FunctionalCore holds the behavioral part of a rule, deduplicated by content hash.
// Multiple Bindings may share the same FunctionalCore pointer when they differ only
// in routing dimensions (scope, version, resource, role, action).
type FunctionalCore struct {
	Condition            *runtimev1.Condition
	DerivedRoleCondition *runtimev1.Condition
	EmitOutput           *runtimev1.Output
	Params               *RowParams
	DerivedRoleParams    *RowParams
	origins              map[string]struct{}
	sum                  uint64
	Effect               effectv1.Effect
	ScopePermissions     policyv1.ScopePermissions
	PolicyKind           policyv1.Kind
	FromRolePolicy       bool
}

// EvaluationKeyTuple is the structured form of a rule's evaluation
// key. Its components are interned.
type EvaluationKeyTuple struct {
	Prefix      unique.Handle[string]
	Resource    unique.Handle[string]
	Principal   unique.Handle[string]
	Role        unique.Handle[string]
	DerivedRole unique.Handle[string]
	Version     unique.Handle[string]
	Scope       unique.Handle[string]
	RuleName    unique.Handle[string]
	RuleID      uint32
}

// Binding ties a routing tuple to a FunctionalCore. Each Binding gets a unique
// uint32 ID used as a position in the bitmap index.
type Binding struct {
	Core                       *FunctionalCore
	AllowActions               map[string]struct{}
	Role                       string
	Scope                      string
	Version                    string
	Resource                   string
	Action                     string
	Principal                  string
	OriginFqn                  string
	OriginDerivedRole          string
	Name                       string
	EvaluationKey              EvaluationKeyTuple
	ID                         uint32
	NoMatchForScopePermissions bool
}

type BindingHandle struct {
	Core                       *FunctionalCore
	AllowActions               map[unique.Handle[string]]struct{}
	Role                       unique.Handle[string]
	Scope                      unique.Handle[string]
	Version                    unique.Handle[string]
	Resource                   unique.Handle[string]
	Action                     unique.Handle[string]
	Principal                  unique.Handle[string]
	OriginFqn                  unique.Handle[string]
	OriginDerivedRole          unique.Handle[string]
	Name                       unique.Handle[string]
	EvaluationKey              EvaluationKeyTuple
	ID                         uint32
	NoMatchForScopePermissions bool
}

func (b *BindingHandle) ToBinding() *Binding {
	if b == nil {
		return nil
	}
	var allow map[string]struct{}
	if b.AllowActions != nil {
		allow = make(map[string]struct{}, len(b.AllowActions))
		for a := range b.AllowActions {
			allow[a.Value()] = struct{}{}
		}
	}
	return &Binding{
		Core:                       b.Core,
		AllowActions:               allow,
		Role:                       stringHandleValue(b.Role),
		Scope:                      stringHandleValue(b.Scope),
		Version:                    stringHandleValue(b.Version),
		Resource:                   stringHandleValue(b.Resource),
		Action:                     stringHandleValue(b.Action),
		Principal:                  stringHandleValue(b.Principal),
		OriginFqn:                  stringHandleValue(b.OriginFqn),
		OriginDerivedRole:          stringHandleValue(b.OriginDerivedRole),
		Name:                       stringHandleValue(b.Name),
		EvaluationKey:              b.EvaluationKey,
		ID:                         b.ID,
		NoMatchForScopePermissions: b.NoMatchForScopePermissions,
	}
}

// IsZero reports whether the tuple is empty, which equivalent to the old empty
// evaluation-key string.
func (t EvaluationKeyTuple) IsZero() bool {
	return t == EvaluationKeyTuple{}
}

// EmptyHandle is the zero unique.Handle[string]. Is equivalent of "".
var EmptyHandle unique.Handle[string]

// makeStringHandle interns s, returning the zero handle for "".
func makeStringHandle(s string) unique.Handle[string] {
	if s == "" {
		return EmptyHandle
	}
	return unique.Make(s)
}

// TODO: replace with HandleStr
func stringHandleValue(h unique.Handle[string]) string {
	if h == EmptyHandle {
		return ""
	}
	return h.Value()
}

// HandleStr returns the interned string for a handle, or "" for the zero handle.
func HandleStr(h unique.Handle[string]) string {
	return stringHandleValue(h)
}

func makeEvaluationKeyTuple(pb *runtimev1.EvaluationKeyTuple, fallbackKey string) EvaluationKeyTuple {
	if pb == nil {
		return EvaluationKeyTuple{RuleName: makeStringHandle(fallbackKey)}
	}
	return EvaluationKeyTuple{
		Prefix:      makeStringHandle(pb.Prefix),
		Resource:    makeStringHandle(pb.Resource),
		Principal:   makeStringHandle(pb.Principal),
		Role:        makeStringHandle(pb.Role),
		DerivedRole: makeStringHandle(pb.DerivedRole),
		Version:     makeStringHandle(pb.Version),
		Scope:       makeStringHandle(pb.Scope),
		RuleName:    makeStringHandle(pb.RuleName),
		RuleID:      pb.RuleId,
	}
}

func (t EvaluationKeyTuple) toProto() *runtimev1.EvaluationKeyTuple {
	return &runtimev1.EvaluationKeyTuple{
		Prefix:      stringHandleValue(t.Prefix),
		Resource:    stringHandleValue(t.Resource),
		Principal:   stringHandleValue(t.Principal),
		Role:        stringHandleValue(t.Role),
		DerivedRole: stringHandleValue(t.DerivedRole),
		Version:     stringHandleValue(t.Version),
		Scope:       stringHandleValue(t.Scope),
		RuleName:    stringHandleValue(t.RuleName),
		RuleId:      t.RuleID,
	}
}

// RowParams holds compiled parameters for a rule or derived role.
type RowParams struct {
	Constants   map[string]any
	CelPrograms []*CelProgram
	Variables   []*runtimev1.Variable
	Key         uint64
}
