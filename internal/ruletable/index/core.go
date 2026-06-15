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

// IsZero reports whether the tuple is empty, which equivalent to the old empty
// evaluation-key string.
func (t EvaluationKeyTuple) IsZero() bool {
	return t == EvaluationKeyTuple{}
}

func makeStringHandle(s string) unique.Handle[string] {
	if s == "" {
		return unique.Handle[string]{}
	}
	return unique.Make(s)
}

func stringHandleValue(h unique.Handle[string]) string {
	var zero unique.Handle[string]
	if h == zero {
		return ""
	}
	return h.Value()
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
