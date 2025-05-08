// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"testing"
	"time"

	celast "github.com/google/cel-go/common/ast"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/conditions"
)

func TestStructMatcher(t *testing.T) {
	tests := []struct {
		expr string
		res  bool
	}{
		{
			expr: "{\"a\": 3}[R.attr.Id] == 4",
			res:  true,
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
		},
		{
			expr: "P.attr.anyMap[R.attr.Id][R.attr.value]",
		},
		{
			expr: "3 in {\"a\": [3, 4]}[R.attr.Id]",
			res:  true,
		},
		{
			expr: "3 in P.attr.anyMap[R.attr.Id]",
		},
		{
			expr: `{1: "red"}.exists(k, v, R.attr.team == v)`,
			res:  true,
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
	for _, test := range tests {
		t.Run(test.expr, func(t *testing.T) {
			ast, issues := env.Compile(test.expr)
			require.Nil(t, issues.Err())
			e := ast.NativeRep().Expr()
			res, e1, err := s.Process(t.Context(), e)
			require.NoError(t, err)
			ep, err := celast.ExprToProto(e1)
			require.NoError(t, err)
			t.Log("result= ", protojson.Format(ep))
			require.Equal(t, test.res, res)
		})
	}
}
