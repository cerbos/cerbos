package codegen

import (
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
)

func TestCELGen(t *testing.T) {
	testCases := []struct {
		name string
		expr *policyv1.Match
		want string
	}{
		{
			name: "simple",
			expr: &policyv1.Match{
				Op: &policyv1.Match_Expr{
					Expr: "a || b && c",
				},
			},
			want: "a || b && c",
		},
		{
			name: "nested",
			expr: &policyv1.Match{
				Op: &policyv1.Match_All{
					All: &policyv1.Match_ExprList{
						Of: []*policyv1.Match{
							{
								Op: &policyv1.Match_Any{
									Any: &policyv1.Match_ExprList{
										Of: []*policyv1.Match{
											{Op: &policyv1.Match_Expr{Expr: "x"}},
											{Op: &policyv1.Match_Expr{Expr: "y"}},
										},
									},
								},
							},
							{
								Op: &policyv1.Match_None{
									None: &policyv1.Match_ExprList{
										Of: []*policyv1.Match{
											{Op: &policyv1.Match_Expr{Expr: "p"}},
											{Op: &policyv1.Match_Expr{Expr: "q"}},
											{Op: &policyv1.Match_Expr{Expr: "r"}},
										},
									},
								},
							},
							{Op: &policyv1.Match_Expr{Expr: "a"}},
							{Op: &policyv1.Match_Expr{Expr: "b"}},
						},
					},
				},
			},
			want: "((x || y) && !(p || q || r) && a && b)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, err := generateMatchCode(tc.expr)
			require.NoError(t, err)
			require.Equal(t, tc.want, have)
		})
	}
}
