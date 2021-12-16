// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/testing/protocmp"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/util"
)

//go:embed testdata/ast_build_expr.yaml
var astBuildExprBlob []byte

type (
	exOp = responsev1.ResourcesQueryPlanResponse_Expression_Operand
)

func getExpectedExpressions(t *testing.T) map[string]*exOp {
	t.Helper()

	var raw map[string]json.RawMessage
	err := yaml.Unmarshal(astBuildExprBlob, &raw)
	require.NoError(t, err)
	res := make(map[string]*exOp, len(raw))
	for k, v := range raw {
		expected := new(exOp)
		b, err := v.MarshalJSON()
		require.NoError(t, err)
		err = util.ReadJSONOrYAML(bytes.NewReader(b), expected)
		require.NoError(t, err)
		res[k] = expected
	}

	return res
}

func Test_buildExpr(t *testing.T) {
	is := require.New(t)
	expected := getExpectedExpressions(t)
	tests := []string{
		`[1,a + 2,"q"]`,
		"z + [2,3]",
		"a[b].c",
		"a[b].c.d",
		"{a:2, b: 3}",
		"x.filter(t, t > 0)",
		"x.map(t, t.upperAscii())",
		"f(a,3)",
		"x.f(a,3)",
	}

	parse := func(s string) *exprpb.Expr {
		ast, iss := conditions.StdEnv.Parse(s)
		is.Nil(iss, iss.Err())
		return ast.Expr()
	}

	for _, expr := range tests {
		t.Run(expr, func(t *testing.T) {
			acc := new(exOp)
			err := buildExpr(parse(expr), acc)
			is.NoError(err)

			if exp, ok := expected[expr]; ok {
				is.Empty(cmp.Diff(exp, acc, protocmp.Transform()))
			} else {
				t.Fatalf("expected result not found for expression: %q", expr)
			}
		})
	}
}
