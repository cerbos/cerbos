// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package test

import (
	"fmt"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"google.golang.org/protobuf/types/known/structpb"
)

type NameMod func(string) string

type PolicyBuilder interface {
	Build() *policyv1.Policy
}

// ResourceRuleBuilder is a builder for resource rules.
type ResourceRuleBuilder struct {
	rule *policyv1.ResourceRule
}

func NewResourceRule(actions ...string) *ResourceRuleBuilder {
	return &ResourceRuleBuilder{
		rule: &policyv1.ResourceRule{
			Actions: actions,
			Effect:  effectv1.Effect_EFFECT_ALLOW,
		},
	}
}

func (rrb *ResourceRuleBuilder) WithRoles(roles ...string) *ResourceRuleBuilder {
	rrb.rule.Roles = append(rrb.rule.Roles, roles...)
	return rrb
}

func (rrb *ResourceRuleBuilder) WithDerivedRoles(roles ...string) *ResourceRuleBuilder {
	rrb.rule.DerivedRoles = append(rrb.rule.DerivedRoles, roles...)
	return rrb
}

func (rrb *ResourceRuleBuilder) WithMatchExpr(expr ...string) *ResourceRuleBuilder {
	rrb.rule.Condition = buildAndCondition(expr...)

	return rrb
}

func (rrb *ResourceRuleBuilder) WithScript(script string) *ResourceRuleBuilder {
	rrb.rule.Condition = &policyv1.Condition{
		Condition: &policyv1.Condition_Script{
			Script: script,
		},
	}

	return rrb
}

func (rrb *ResourceRuleBuilder) WithEffect(effect effectv1.Effect) *ResourceRuleBuilder {
	rrb.rule.Effect = effect
	return rrb
}

func (rrb *ResourceRuleBuilder) Build() *policyv1.ResourceRule {
	return rrb.rule
}

// ResourcePolicyBuilder is a builder for resource policies.
type ResourcePolicyBuilder struct {
	rp *policyv1.ResourcePolicy
}

func NewResourcePolicyBuilder(resource, version string) *ResourcePolicyBuilder {
	return &ResourcePolicyBuilder{
		rp: &policyv1.ResourcePolicy{
			Constants: &policyv1.Constants{
				Local: make(map[string]*structpb.Value),
			},
			Variables: &policyv1.Variables{
				Local: make(map[string]string),
			},
			Resource: resource,
			Version:  version,
		},
	}
}

func (rpb *ResourcePolicyBuilder) WithDerivedRolesImports(imp ...string) *ResourcePolicyBuilder {
	rpb.rp.ImportDerivedRoles = append(rpb.rp.ImportDerivedRoles, imp...)
	return rpb
}

func (rpb *ResourcePolicyBuilder) WithLocalConstant(name string, value *structpb.Value) *ResourcePolicyBuilder {
	rpb.rp.Constants.Local[name] = value
	return rpb
}

func (rpb *ResourcePolicyBuilder) WithLocalVariable(name, value string) *ResourcePolicyBuilder {
	rpb.rp.Variables.Local[name] = value
	return rpb
}

func (rpb *ResourcePolicyBuilder) WithRules(rules ...*policyv1.ResourceRule) *ResourcePolicyBuilder {
	rpb.rp.Rules = append(rpb.rp.Rules, rules...)
	return rpb
}

func (rpb *ResourcePolicyBuilder) Build() *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: rpb.rp,
		},
	}
}

func buildAndCondition(expr ...string) *policyv1.Condition {
	allExpr := make([]*policyv1.Match, len(expr))
	for i, e := range expr {
		allExpr[i] = &policyv1.Match{Op: &policyv1.Match_Expr{Expr: e}}
	}

	return &policyv1.Condition{
		Condition: &policyv1.Condition_Match{
			Match: &policyv1.Match{
				Op: &policyv1.Match_All{
					All: &policyv1.Match_ExprList{
						Of: allExpr,
					},
				},
			},
		},
	}
}

func GenDisabledResourcePolicy(mod NameMod) *policyv1.Policy {
	p := GenResourcePolicy(mod)
	p.Disabled = true
	return p
}

func GenDisabledRolePolicy(mod NameMod) *policyv1.Policy {
	p := GenRolePolicy(mod)
	p.Disabled = true
	return p
}

func GenScopedResourcePolicy(scope string, mod NameMod) *policyv1.Policy {
	p := GenResourcePolicy(mod)
	p.GetResourcePolicy().Scope = scope
	return p
}

// GenResourcePolicy generates a sample resource policy with some names modified by the NameMod.
func GenResourcePolicy(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource:           mod("leave_request"),
				Version:            "default",
				ImportDerivedRoles: []string{mod("my_derived_roles")},
				Constants: &policyv1.Constants{
					Import: []string{mod("my_constants")},
				},
				Variables: &policyv1.Variables{
					Import: []string{mod("my_variables")},
				},
				Rules: []*policyv1.ResourceRule{
					{
						Actions: []string{"*"},
						Roles:   []string{"admin"},
						Effect:  effectv1.Effect_EFFECT_ALLOW,
					},

					{
						Actions:      []string{"create"},
						DerivedRoles: []string{"employee_that_owns_the_record"},
						Effect:       effectv1.Effect_EFFECT_ALLOW,
					},

					{
						Actions:      []string{"view:*"},
						DerivedRoles: []string{"employee_that_owns_the_record", "direct_manager"},
						Effect:       effectv1.Effect_EFFECT_ALLOW,
					},

					{
						Actions:      []string{"approve"},
						DerivedRoles: []string{"direct_manager"},
						Effect:       effectv1.Effect_EFFECT_ALLOW,
						Condition: &policyv1.Condition{
							Condition: &policyv1.Condition_Match{
								Match: &policyv1.Match{
									Op: &policyv1.Match_Expr{Expr: `request.resource.attr.status == "PENDING_APPROVAL"`},
								},
							},
						},
					},
				},
			},
		},
	}
}

// GenRolePolicy generates a sample role policy with some names modified by the NameMod.
func GenRolePolicy(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_RolePolicy{
			RolePolicy: &policyv1.RolePolicy{
				Version: namer.DefaultVersion,
				PolicyType: &policyv1.RolePolicy_Role{
					Role: mod("acme_admin"),
				},
				Rules: []*policyv1.RoleRule{
					{
						Resource: mod("leave_request"),
						AllowActions: []string{
							mod("create"),
						},
					},
				},
			},
		},
	}
}

// PrincipalRuleBuilder is a builder for principal rules.
type PrincipalRuleBuilder struct {
	rule *policyv1.PrincipalRule
}

func NewPrincipalRuleBuilder(resource string) *PrincipalRuleBuilder {
	return &PrincipalRuleBuilder{
		rule: &policyv1.PrincipalRule{
			Resource: resource,
		},
	}
}

func (prb *PrincipalRuleBuilder) AllowAction(action string) *PrincipalRuleBuilder {
	return prb.addAction(action, effectv1.Effect_EFFECT_ALLOW, nil)
}

func (prb *PrincipalRuleBuilder) DenyAction(action string) *PrincipalRuleBuilder {
	return prb.addAction(action, effectv1.Effect_EFFECT_DENY, nil)
}

func (prb *PrincipalRuleBuilder) AllowActionWhenMatch(action string, expr ...string) *PrincipalRuleBuilder {
	return prb.addAction(action, effectv1.Effect_EFFECT_ALLOW, buildAndCondition(expr...))
}

func (prb *PrincipalRuleBuilder) DenyActionWhenMatch(action string, expr ...string) *PrincipalRuleBuilder {
	return prb.addAction(action, effectv1.Effect_EFFECT_DENY, buildAndCondition(expr...))
}

func (prb *PrincipalRuleBuilder) AllowActionWhenScript(action, script string) *PrincipalRuleBuilder {
	return prb.addAction(action, effectv1.Effect_EFFECT_ALLOW, &policyv1.Condition{Condition: &policyv1.Condition_Script{Script: script}})
}

func (prb *PrincipalRuleBuilder) DenyActionWhenScript(action, script string) *PrincipalRuleBuilder {
	return prb.addAction(action, effectv1.Effect_EFFECT_DENY, &policyv1.Condition{Condition: &policyv1.Condition_Script{Script: script}})
}

func (prb *PrincipalRuleBuilder) addAction(action string, effect effectv1.Effect, comp *policyv1.Condition) *PrincipalRuleBuilder {
	prb.rule.Actions = append(prb.rule.Actions, &policyv1.PrincipalRule_Action{
		Action:    action,
		Effect:    effect,
		Condition: comp,
	})

	return prb
}

func (prb *PrincipalRuleBuilder) Build() *policyv1.PrincipalRule {
	return prb.rule
}

// PrincipalPolicyBuilder is a builder for principal policies.
type PrincipalPolicyBuilder struct {
	pp *policyv1.PrincipalPolicy
}

func NewPrincipalPolicyBuilder(principal, version string) *PrincipalPolicyBuilder {
	return &PrincipalPolicyBuilder{
		pp: &policyv1.PrincipalPolicy{
			Principal: principal,
			Version:   version,
			Constants: &policyv1.Constants{
				Local: make(map[string]*structpb.Value),
			},
			Variables: &policyv1.Variables{
				Local: make(map[string]string),
			},
		},
	}
}

func (ppb *PrincipalPolicyBuilder) WithLocalConstant(name string, value *structpb.Value) *PrincipalPolicyBuilder {
	ppb.pp.Constants.Local[name] = value
	return ppb
}

func (ppb *PrincipalPolicyBuilder) WithLocalVariable(name, value string) *PrincipalPolicyBuilder {
	ppb.pp.Variables.Local[name] = value
	return ppb
}

func (ppb *PrincipalPolicyBuilder) WithRules(rules ...*policyv1.PrincipalRule) *PrincipalPolicyBuilder {
	ppb.pp.Rules = append(ppb.pp.Rules, rules...)
	return ppb
}

func (ppb *PrincipalPolicyBuilder) Build() *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_PrincipalPolicy{
			PrincipalPolicy: ppb.pp,
		},
	}
}

// RoleRuleBuilder is a builder for resource rules.
type RoleRuleBuilder struct {
	rule *policyv1.RoleRule
}

func NewRoleRule(resource string, actions ...string) *RoleRuleBuilder {
	return &RoleRuleBuilder{
		rule: &policyv1.RoleRule{
			Resource:     resource,
			AllowActions: actions,
		},
	}
}

func (rrb *RoleRuleBuilder) Build() *policyv1.RoleRule {
	return rrb.rule
}

// RolePolicyBuilder is a builder for role policies.
type RolePolicyBuilder struct {
	rp *policyv1.RolePolicy
}

func NewRolePolicyBuilder(role string) *RolePolicyBuilder {
	return &RolePolicyBuilder{
		rp: &policyv1.RolePolicy{
			PolicyType: &policyv1.RolePolicy_Role{
				Role: role,
			},
		},
	}
}

func (rpb *RolePolicyBuilder) WithRules(rules ...*policyv1.RoleRule) *RolePolicyBuilder {
	rpb.rp.Rules = append(rpb.rp.Rules, rules...)
	return rpb
}

func (rpb *RolePolicyBuilder) Build() *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_RolePolicy{
			RolePolicy: rpb.rp,
		},
	}
}

func GenDisabledPrincipalPolicy(mod NameMod) *policyv1.Policy {
	p := GenPrincipalPolicy(mod)
	p.Disabled = true
	return p
}

func GenPrincipalPolicy(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_PrincipalPolicy{
			PrincipalPolicy: &policyv1.PrincipalPolicy{
				Principal: mod("donald_duck"),
				Version:   "default",
				Constants: &policyv1.Constants{
					Import: []string{mod("my_constants")},
				},
				Variables: &policyv1.Variables{
					Import: []string{mod("my_variables")},
				},
				Rules: []*policyv1.PrincipalRule{
					{
						Resource: mod("leave_request"),
						Actions: []*policyv1.PrincipalRule_Action{
							{
								Action: "*",
								Effect: effectv1.Effect_EFFECT_ALLOW,
								Condition: &policyv1.Condition{
									Condition: &policyv1.Condition_Match{
										Match: &policyv1.Match{
											Op: &policyv1.Match_Expr{Expr: "request.resource.attr.dev_record == true"},
										},
									},
								},
							},
						},
					},
					{
						Resource: mod("salary_record"),
						Actions: []*policyv1.PrincipalRule_Action{
							{
								Action: "*",
								Effect: effectv1.Effect_EFFECT_DENY,
							},
						},
					},
				},
			},
		},
	}
}

type DerivedRolesBuilder struct {
	dr *policyv1.DerivedRoles
}

func NewDerivedRolesBuilder(name string) *DerivedRolesBuilder {
	return &DerivedRolesBuilder{
		dr: &policyv1.DerivedRoles{Name: name},
	}
}

func (drb *DerivedRolesBuilder) AddRole(name string, parentRoles ...string) *DerivedRolesBuilder {
	return drb.addRoleDef(name, parentRoles, nil)
}

func (drb *DerivedRolesBuilder) AddRoleWithMatch(name string, parentRoles []string, expr ...string) *DerivedRolesBuilder {
	return drb.addRoleDef(name, parentRoles, buildAndCondition(expr...))
}

func (drb *DerivedRolesBuilder) addRoleDef(name string, parentRoles []string, comp *policyv1.Condition) *DerivedRolesBuilder {
	drb.dr.Definitions = append(drb.dr.Definitions, &policyv1.RoleDef{Name: name, ParentRoles: parentRoles, Condition: comp})
	return drb
}

func (drb *DerivedRolesBuilder) Build() *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_DerivedRoles{
			DerivedRoles: drb.dr,
		},
	}
}

func GenDisabledDerivedRoles(mod NameMod) *policyv1.Policy {
	p := GenDerivedRoles(mod)
	p.Disabled = true
	return p
}

func GenDerivedRoles(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_DerivedRoles{
			DerivedRoles: &policyv1.DerivedRoles{
				Name: mod("my_derived_roles"),
				Constants: &policyv1.Constants{
					Local: map[string]*structpb.Value{
						"answer": structpb.NewNumberValue(42), //nolint:mnd
					},
				},
				Variables: &policyv1.Variables{
					Local: map[string]string{
						"geography": "request.resource.attr.geography",
					},
				},
				Definitions: []*policyv1.RoleDef{
					{
						Name:        "admin",
						ParentRoles: []string{"admin"},
					},
					{
						Name:        "employee_that_owns_the_record",
						ParentRoles: []string{"employee"},
						Condition: &policyv1.Condition{
							Condition: &policyv1.Condition_Match{
								Match: &policyv1.Match{
									Op: &policyv1.Match_Expr{Expr: `R.attr.owner == P.id`},
								},
							},
						},
					},
					{
						Name:        "any_employee",
						ParentRoles: []string{"employee"},
					},
					{
						Name:        "direct_manager",
						ParentRoles: []string{"manager"},
						Condition: buildAndCondition(
							"request.resource.attr.geography == request.principal.attr.geography",
							"request.resource.attr.geography == request.principal.attr.managed_geographies",
						),
					},
				},
			},
		},
	}
}

func GenDisabledExportConstants(mod NameMod) *policyv1.Policy {
	p := GenExportConstants(mod)
	p.Disabled = true
	return p
}

func GenExportConstants(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ExportConstants{
			ExportConstants: &policyv1.ExportConstants{
				Name: mod("my_constants"),
				Definitions: map[string]*structpb.Value{
					"answer": structpb.NewNumberValue(42), //nolint:mnd
				},
			},
		},
	}
}

func GenDisabledExportVariables(mod NameMod) *policyv1.Policy {
	p := GenExportVariables(mod)
	p.Disabled = true
	return p
}

func GenExportVariables(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "api.cerbos.dev/v1",
		PolicyType: &policyv1.Policy_ExportVariables{
			ExportVariables: &policyv1.ExportVariables{
				Name: mod("my_variables"),
				Definitions: map[string]string{
					"geography": "request.resource.attr.geography",
				},
			},
		},
	}
}

func PrefixAndSuffix(prefix, suffix string) NameMod {
	return func(name string) string {
		return fmt.Sprintf("%s_%s_%s", prefix, name, suffix)
	}
}

func Suffix(suffix string) NameMod {
	return func(name string) string {
		return fmt.Sprintf("%s_%s", name, suffix)
	}
}

func NoMod() NameMod {
	return func(name string) string { return name }
}
