// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
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

// ToRuleRow reconstructs a RuleTable_RuleRow proto from this Binding.
func (b *Binding) ToRuleRow() *runtimev1.RuleTable_RuleRow {
	row := &runtimev1.RuleTable_RuleRow{
		OriginFqn:            b.OriginFqn,
		Resource:             b.Resource,
		Role:                 b.Role,
		Scope:                b.Scope,
		Version:              b.Version,
		OriginDerivedRole:    b.OriginDerivedRole,
		Name:                 b.Name,
		Principal:            b.Principal,
		EvaluationKey:        b.EvaluationKey,
		Effect:               b.Core.Effect,
		Condition:            b.Core.Condition,
		DerivedRoleCondition: b.Core.DerivedRoleCondition,
		EmitOutput:           b.Core.EmitOutput,
		ScopePermissions:     b.Core.ScopePermissions,
		PolicyKind:           b.Core.PolicyKind,
		FromRolePolicy:       b.Core.FromRolePolicy,
		Params:               rowParamsToProto(b.Core.Params),
		DerivedRoleParams:    rowParamsToProto(b.Core.DerivedRoleParams),
	}

	if b.AllowActions != nil {
		actions := make(map[string]*emptypb.Empty, len(b.AllowActions))
		for a := range b.AllowActions {
			actions[a] = &emptypb.Empty{}
		}
		row.ActionSet = &runtimev1.RuleTable_RuleRow_AllowActions_{
			AllowActions: &runtimev1.RuleTable_RuleRow_AllowActions{Actions: actions},
		}
	} else {
		row.ActionSet = &runtimev1.RuleTable_RuleRow_Action{Action: b.Action}
	}

	return row
}

func rowParamsToProto(p *RowParams) *runtimev1.RuleTable_RuleRow_Params {
	if p == nil {
		return nil
	}

	var constants map[string]*structpb.Value
	if len(p.Constants) > 0 {
		constants = make(map[string]*structpb.Value, len(p.Constants))
		for k, v := range p.Constants {
			sv, err := structpb.NewValue(v)
			if err != nil {
				continue
			}
			constants[k] = sv
		}
	}

	return &runtimev1.RuleTable_RuleRow_Params{
		OrderedVariables: p.Variables,
		Constants:        constants,
	}
}
