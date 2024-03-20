// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package matchers

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

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
	}
	for _, test := range tests {
		t.Run(test.expr, func(t *testing.T) {
			ast, issues := conditions.StdEnv.Compile(test.expr)
			require.Nil(t, issues.Err())
			ex, err := cel.AstToParsedExpr(ast)
			require.NoError(t, err)
			s := NewExpressionProcessor()
			res, _, err := s.Process(ex.Expr)
			require.NoError(t, err)
			require.Equal(t, res, test.res)
		})
	}
}
