package policy

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
)

var (
	policy01 = &policyv1.Policy{
		ApiVersion: "paams.dev/v1",
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: &policyv1.ResourcePolicy{
				Resource:           "leave_request",
				Version:            "20210210",
				ImportDerivedRoles: []string{"my_derived_roles"},
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
										"$resource.attr.status == PENDING_APPROVAL",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy02 = &policyv1.Policy{
		ApiVersion: "paams.dev/v1",
		PolicyType: &policyv1.Policy_PrincipalPolicy{
			PrincipalPolicy: &policyv1.PrincipalPolicy{
				Principal: "donald_duck",
				Version:   "20210210",
				Rules: []*policyv1.PrincipalRule{
					{
						Resource: "leave_request",
						Actions: []*policyv1.PrincipalRule_Action{
							{
								Action: "*",
								Effect: sharedv1.Effect_EFFECT_ALLOW,
								Condition: &policyv1.Computation{
									Computation: &policyv1.Computation_Match{
										Match: &policyv1.Match{
											Expr: []string{
												"$resource.attr.dev_record == true",
											},
										},
									},
								},
							},
						},
					},
					{
						Resource: "salary_record",
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

	derivedRoles01 = &policyv1.DerivedRoles{
		ApiVersion: "paams.dev/v1",
		Name:       "my_derived_roles",
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
								"$resource.attr.geography == $principal.attr.geography",
								"$resource.attr.geography == $principal.attr.managed_geographies",
							},
						},
					},
				},
			},
		},
	}
)

func TestLoadFromJSONOrYAML(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		want    protoreflect.ProtoMessage
		have    protoreflect.ProtoMessage
		wantErr bool
	}{
		{
			name:  "YAML ResourcePolicy",
			input: "../testdata/formats/resource_policy_01.yaml",
			want:  policy01,
			have:  &policyv1.Policy{},
		},
		{
			name:  "JSON ResourcePolicy",
			input: "../testdata/formats/resource_policy_01.json",
			want:  policy01,
			have:  &policyv1.Policy{},
		},
		{
			name:  "YAML PrincipalPolicy",
			input: "../testdata/formats/principal_policy_01.yaml",
			want:  policy02,
			have:  &policyv1.Policy{},
		},
		{
			name:  "JSON PrincipalPolicy",
			input: "../testdata/formats/principal_policy_01.json",
			want:  policy02,
			have:  &policyv1.Policy{},
		},
		{
			name:  "YAML DerivedRoles",
			input: "../testdata/formats/derived_roles_01.yaml",
			want:  derivedRoles01,
			have:  &policyv1.DerivedRoles{},
		},
		{
			name:  "JSON DerivedRoles",
			input: "../testdata/formats/derived_roles_01.json",
			want:  derivedRoles01,
			have:  &policyv1.DerivedRoles{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			//fmt.Println(protojson.Format(tc.want))
			f, err := os.Open(tc.input)
			require.NoError(t, err)

			defer f.Close()

			err = loadFromJSONOrYAML(f, tc.have)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tc.want, tc.have, protocmp.Transform()))
			}
		})
	}
}
