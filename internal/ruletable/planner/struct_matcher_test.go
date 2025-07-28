// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"regexp"
	"testing"
	"time"

	"github.com/google/cel-go/parser"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/conditions"
)

func TestStructMatcher(t *testing.T) {
	tests := []struct {
		expr string
		want string
	}{
		{
			expr: "{\"a\": 3}[R.attr.Id] == 4",
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
			want: `R.id == "a1" && "OWNER" == {"role": "OWNER"}.role`,
		},
		{
			expr: "P.attr.anyMap[R.attr.Id][R.attr.value]",
		},
		{
			expr: "3 in {\"a\": [3, 4]}[R.attr.Id]",
			want: `R.attr.Id == "a" && 3 in [3, 4]`,
		},
		{
			expr: "3 in P.attr.anyMap[R.attr.Id]",
		},
		{
			expr: `{1: ["red", "square"], 2: ["blue", "triangle"], 3: ["black", "circle"]}.exists(k, v, R.attr.color == v[0] && R.attr.shape == v[1])`,
			want: `R.attr.color == "red" && R.attr.shape == "square" || R.attr.color == "blue" && R.attr.shape == "triangle" ||
        R.attr.color == "black" && R.attr.shape == "circle"`,
		},
		{
			expr: "{1: 1}.exists(k, v, k == v)",
			want: "true",
		},
		{
			expr: `{1: {"colors": ["red"]}}.exists(k, v, R.attr.color in v["colors"])`,
			want: `R.attr.color in ["red"]`,
		},
		{
			expr: `{1: {"colors": ["red"]}}.exists(v, R.attr.color == v)`,
			want: `R.attr.color == 1`,
		},
		{
			expr: `[1, 2].exists(v, R.attr.color == v)`,
			want: `R.attr.color == 1 || R.attr.color == 2`,
		},
		{
			expr: `[1, 2].exists(i, v, R.attr.color == v && R.attr.size == i)`,
			want: `R.attr.color == 1 && R.attr.size == 0 || R.attr.color == 2 && R.attr.size == 1`,
		},
	}
	env := conditions.StdEnv
	knownVars := make(map[string]any)
	p, err := newPartialEvaluator(env, knownVars, time.Now)
	require.NoError(t, err)
	s := newExpressionProcessor(p)
	for _, tc := range tests {
		t.Run(tc.expr, func(t *testing.T) {
			ast, issues := env.Compile(tc.expr)
			require.Nil(t, issues.Err())
			e := ast.NativeRep().Expr()
			matched, e1, err := s.Process(t.Context(), e)
			require.NoError(t, err)
			if tc.want == "" {
				require.False(t, matched)
			} else {
				require.True(t, matched)
				unparsed, err := parser.Unparse(e1, nil)
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(stripWs(tc.want), stripWs(unparsed)))
			}
		})
	}
}

func stripWs(s string) string {
	r := regexp.MustCompile(`\s+`)
	return string(r.ReplaceAll([]byte(s), []byte(" ")))
}
