package policy_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/policy"
)

var (
	policy01 = policyv1.Policy{
		Version: "20210131",
		Id:      "my_policy",
		Subjects: &policyv1.Policy_DynamicRoles{
			DynamicRoles: &policyv1.DynamicRoleList{
				Definitions: []*policyv1.DynamicRole{
					{
						Name:        "employee_that_owns_the_record",
						ParentRoles: []string{"employee"},
						Computation: &policyv1.Computation{
							Computation: &policyv1.Computation_Script{
								Script: "is_owner { resource.owner == request.principal.id }",
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
										"resource.attr.geography == principal.attr.geography",
										"resource.attr.geography == principal.attr.managed_geographies",
										"resource.attr.team IN principal.attr.managed_teams",
									},
								},
							},
						},
					},
				},
			},
		},
		Resources: []*policyv1.Resource{
			{
				Resource: "leave_request",
				Actions: []*policyv1.Action{
					{
						Action:   "create",
						Subjects: []string{"employee_that_owns_the_record"},
						Effect:   policyv1.Effect_EFFECT_ALLOW,
					},
					{
						Action:   "view:public",
						Subjects: []string{"any_employee"},
						Effect:   policyv1.Effect_EFFECT_ALLOW,
						Condition: &policyv1.Computation{
							Computation: &policyv1.Computation_Match{
								Match: &policyv1.Match{
									Expr: []string{
										"resource.state == APPROVED",
										"resource.upcoming_request == true",
									},
								},
							},
						},
					},
				},
			},
		},
	}
)

func TestLoadPolicy(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		want    *policyv1.Policy
		wantErr bool
	}{
		{
			name:  "Valid YAML",
			input: "testdata/load_policy_01.yaml",
			want:  &policy01,
		},
		{
			name:  "Valid JSON",
			input: "testdata/load_policy_01.json",
			want:  &policy01,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			//fmt.Println(protojson.Format(tc.want))
			f, err := os.Open(tc.input)
			require.NoError(t, err)

			defer f.Close()

			have, err := policy.LoadPolicy(f)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tc.want, have, protocmp.Transform()))
			}
		})
	}
}
