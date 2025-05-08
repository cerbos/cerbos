// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"regexp"
	"testing"
	"time"

	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/cerbos/cerbos/internal/conditions"
)

func TestStructMatcher(t *testing.T) {
	tests := []struct {
		expr string
		res  bool
		want string
	}{
		{
			expr: "{\"a\": 3}[R.attr.Id] == 4",
			res:  true,
			want: `R.attr.Id == "a" && 4 == 3`,
		},
		{
			expr: "4 == {\"a\": 3}[R.attr.Id]", // can't swap args
		},
		{
			expr: "P.attr.anyMap[R.attr.Id] == R.attr.value",
		},
		{
			expr: `{"a1": {"role": "OWNER"}}[R.id].role == "OWNER"`,
			res:  true,
			want: `R.id == "a1" && "OWNER" == {"role": "OWNER"}.role`,
		},
		{
			expr: "P.attr.anyMap[R.attr.Id][R.attr.value]",
		},
		{
			expr: "3 in {\"a\": [3, 4]}[R.attr.Id]",
			res:  true,
			want: `R.attr.Id == "a" && 3 in [3, 4]`,
		},
		{
			expr: "3 in P.attr.anyMap[R.attr.Id]",
		},
		{
			expr: `{1: ["red", "square"], 2: ["blue", "triangle"], 3: ["black", "circle"]}.exists(k, v, R.attr.color == v[0] && R.attr.shape == v[1])`,
			want: `R.attr.color == "red" && R.attr.shape == "square" || R.attr.color == "blue" && R.attr.shape == "triangle" ||
        R.attr.color == "black" && R.attr.shape == "circle"`,
			res: true,
		},
	}
	env := conditions.StdEnv
	knownVars := make(map[string]any)
	// env, knownVars, variables := setupEnv(t)
	nowFn := func() time.Time {
		return time.Now()
	}
	p, err := newPartialEvaluator(env, knownVars, nowFn)
	require.NoError(t, err)
	s := newExpressionProcessor(p)
	for _, tc := range tests {
		t.Run(tc.expr, func(t *testing.T) {
			ast, issues := env.Compile(tc.expr)
			require.Nil(t, issues.Err())
			e := ast.NativeRep().Expr()
			res, e1, err := s.Process(t.Context(), e)
			require.NoError(t, err)
			require.Equal(t, tc.res, res)
			if tc.res {
				unparsed, err := unparseExpr(t, e1)
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(stripWs(tc.want), stripWs(unparsed)))
			}
		})
	}
}
func stripWs(s string) string {
	r := regexp.MustCompile("\\s+")
	return string(r.ReplaceAll([]byte(s), []byte(" ")))
}
func unparseExpr(t *testing.T, expr celast.Expr) (string, error) {
	t.Helper()
	protoExpr, err := celast.ExprToProto(expr)
	require.NoError(t, err)

	astExpr, err := celast.ProtoToExpr(protoExpr)
	require.NoError(t, err)

	checkedExpr := &exprpb.CheckedExpr{
		Expr:       protoExpr,
		SourceInfo: &exprpb.SourceInfo{},
	}
	srcInfo, err := celast.ProtoToSourceInfo(checkedExpr.SourceInfo)
	require.NoError(t, err)

	source, err := parser.Unparse(astExpr, srcInfo)
	require.NoError(t, err)
	return source, nil
}
