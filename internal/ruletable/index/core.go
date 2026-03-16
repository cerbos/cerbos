// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
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
	EvaluationKey              string
	ID                         uint32
	NoMatchForScopePermissions bool
}

// RowParams holds compiled parameters for a rule or derived role.
type RowParams struct {
	Key         string
	Constants   map[string]any
	CelPrograms []*CelProgram
	Variables   []*runtimev1.Variable
}
