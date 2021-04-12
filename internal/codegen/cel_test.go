package codegen

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/util"
)

func TestCELGen(t *testing.T) {
	x := &policyv1.Match{
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
					{Op: &policyv1.Match_Expr{Expr: "a"}},
					{Op: &policyv1.Match_Expr{Expr: "b"}},
				},
			},
		},
	}

	b := new(bytes.Buffer)
	require.NoError(t, util.WriteYAML(b, x))
	fmt.Println(b.String())

	p, err := generateMatchCode(x)
	require.NoError(t, err)
	fmt.Println(p)
}
