package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	"github.com/charithe/menshen/pkg/policy"
	"github.com/charithe/menshen/pkg/test"
)

func TestReadPolicy(t *testing.T) {
	dir := test.PathToDir(t, "policy_formats")

	testCases := []struct {
		name    string
		input   string
		want    protoreflect.ProtoMessage
		wantErr bool
	}{
		{
			name:  "YAML ResourcePolicy",
			input: filepath.Join(dir, "resource_policy_01.yaml"),
			want:  mkResourcePolicy(),
		},
		{
			name:  "JSON ResourcePolicy",
			input: filepath.Join(dir, "resource_policy_01.json"),
			want:  mkResourcePolicy(),
		},
		{
			name:  "YAML PrincipalPolicy",
			input: filepath.Join(dir, "principal_policy_01.yaml"),
			want:  mkPrincipalPolicy(),
		},
		{
			name:  "JSON PrincipalPolicy",
			input: filepath.Join(dir, "principal_policy_01.json"),
			want:  mkPrincipalPolicy(),
		},
		{
			name:  "YAML DerivedRoles",
			input: filepath.Join(dir, "derived_roles_01.yaml"),
			want:  mkDerivedRoles(),
		},
		{
			name:  "JSON DerivedRoles",
			input: filepath.Join(dir, "derived_roles_01.json"),
			want:  mkDerivedRoles(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			//fmt.Println(protojson.Format(tc.want))
			f, err := os.Open(tc.input)
			require.NoError(t, err)

			defer f.Close()

			have, _, err := policy.ReadPolicy(f)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tc.want, have, protocmp.Transform()))
			}
		})
	}
}

func TestValidate(t *testing.T) {
	type validator interface {
		Validate() error
	}

	testCases := []struct {
		name  string
		input func() validator
	}{
		{
			name: "type=ResourcePolicy;issue=BadAPIVersion",
			input: func() validator {
				obj := mkResourcePolicy()
				obj.ApiVersion = "something"
				return obj
			},
		},
		{
			name: "type=ResourcePolicy;issue=BadResourceName",
			input: func() validator {
				obj := mkResourcePolicy()
				rp := obj.GetResourcePolicy()
				rp.Resource = "a?;#"
				obj.PolicyType = &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}

				return obj
			},
		},
		{
			name: "type=ResourcePolicy;issue=EmptyResourceName",
			input: func() validator {
				obj := mkResourcePolicy()
				rp := obj.GetResourcePolicy()
				rp.Resource = ""
				obj.PolicyType = &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}

				return obj
			},
		},
		{
			name: "type=ResourcePolicy;issue=NoResourceRules",
			input: func() validator {
				obj := mkResourcePolicy()
				rp := obj.GetResourcePolicy()
				rp.Rules = nil
				obj.PolicyType = &policyv1.Policy_ResourcePolicy{ResourcePolicy: rp}

				return obj
			},
		},
		{
			name: "type=PrincipalPolicy;issue=BadAPIVersion",
			input: func() validator {
				obj := mkPrincipalPolicy()
				obj.ApiVersion = "something"
				return obj
			},
		},
		// TODO (cell) Cover other validation rules
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj := tc.input()
			require.Error(t, obj.Validate())
		})
	}
}

func mkResourcePolicy() *policyv1.Policy {
	return &policyv1.Policy{
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
										`$resource.attr.status == "PENDING_APPROVAL"`,
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

func mkPrincipalPolicy() *policyv1.Policy {
	return &policyv1.Policy{
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
}

func mkDerivedRoles() *policyv1.Policy {
	return &policyv1.Policy{
		ApiVersion: "paams.dev/v1",
		PolicyType: &policyv1.Policy_DerivedRoles{
			DerivedRoles: &policyv1.DerivedRoles{
				Name: "my_derived_roles",
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
			},
		},
	}
}
