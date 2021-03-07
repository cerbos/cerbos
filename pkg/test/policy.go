package test

import (
	"fmt"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
)

type NameMod func(string) string

func GenResourcePolicy(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "paams.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource:           mod("leave_request"),
				Version:            "default",
				ImportDerivedRoles: []string{mod("my_derived_roles")},
				Rules: []*policyv1.ResourceRule{
					{
						Action: "*",
						Roles:  []string{"admin"},
						Effect: sharedv1.Effect_EFFECT_ALLOW,
					},

					{
						Action:       "create",
						DerivedRoles: []string{"employee_that_owns_the_record"},
						Effect:       sharedv1.Effect_EFFECT_ALLOW,
					},

					{
						Action:       "view:*",
						DerivedRoles: []string{"employee_that_owns_the_record", "direct_manager"},
						Effect:       sharedv1.Effect_EFFECT_ALLOW,
					},

					{
						Action:       "approve",
						DerivedRoles: []string{"direct_manager"},
						Effect:       sharedv1.Effect_EFFECT_ALLOW,
						Condition: &policyv1.Computation{
							Computation: &policyv1.Computation_Match{
								Match: &policyv1.Match{
									Expr: []string{
										`request.resource.attr.status == "PENDING_APPROVAL"`,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func GenPrincipalPolicy(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "paams.dev/v1",
		PolicyType: &policyv1.Policy_PrincipalPolicy{
			PrincipalPolicy: &policyv1.PrincipalPolicy{
				Principal: mod("donald_duck"),
				Version:   "default",
				Rules: []*policyv1.PrincipalRule{
					{
						Resource: mod("leave_request"),
						Actions: []*policyv1.PrincipalRule_Action{
							{
								Action: "*",
								Effect: sharedv1.Effect_EFFECT_ALLOW,
								Condition: &policyv1.Computation{
									Computation: &policyv1.Computation_Match{
										Match: &policyv1.Match{
											Expr: []string{
												"request.resource.attr.dev_record == true",
											},
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
								Effect: sharedv1.Effect_EFFECT_DENY,
							},
						},
					},
				},
			},
		},
	}
}

func GenDerivedRoles(mod NameMod) *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "paams.dev/v1",
		PolicyType: &policyv1.Policy_DerivedRoles{
			DerivedRoles: &policyv1.DerivedRoles{
				Name: mod("my_derived_roles"),
				Definitions: []*policyv1.RoleDef{
					{
						Name:        "admin",
						ParentRoles: []string{"admin"},
					},
					{
						Name:        "employee_that_owns_the_record",
						ParentRoles: []string{"employee"},
						Computation: &policyv1.Computation{
							Computation: &policyv1.Computation_Script{
								Script: "input.resource.attr.owner == input.principal.id",
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
						Computation: &policyv1.Computation{
							Computation: &policyv1.Computation_Match{
								Match: &policyv1.Match{
									Expr: []string{
										"request.resource.attr.geography == request.principal.attr.geography",
										"request.resource.attr.geography == request.principal.attr.managed_geographies",
									},
								},
							},
						},
					},
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
