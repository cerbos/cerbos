// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/google/cel-go/cel"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestResourceAttributeNames(t *testing.T) {
	name := "a"
	fqns := conditions.ResourceAttributeNames(name)
	require.Equal(t, []string{"R.attr.a", "request.resource.attr.a"}, fqns)
}

func TestExpandAbbrev(t *testing.T) {
	testCases := []struct {
		input string
		want  string
	}{
		{
			input: "R",
			want:  "request.resource",
		},
		{
			input: "P",
			want:  "request.principal",
		},
		{
			input: "V",
			want:  "variables",
		},
		{
			input: "R.attr.department",
			want:  "request.resource.attr.department",
		},
		{
			input: "P.attr.department",
			want:  "request.principal.attr.department",
		},
		{
			input: "V.is_admin",
			want:  "variables.is_admin",
		},
		{
			input: "G.environment",
			want:  "globals.environment",
		},
		{
			input: "request.principal.attr.department",
			want:  "request.principal.attr.department",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			have := conditions.ExpandAbbrev(tc.input)
			require.Equal(t, tc.want, have)
		})
	}
}

func TestConstantExprs(t *testing.T) {
	constantExprs := map[string]*expr.CheckedExpr{
		"true":  conditions.TrueExpr,
		"false": conditions.FalseExpr,
	}

	for source, have := range constantExprs {
		t.Run(source, func(t *testing.T) {
			ast, issues := conditions.StdEnv.Compile(source)
			require.NoError(t, issues.Err())

			want, err := cel.AstToCheckedExpr(ast)
			require.NoError(t, err)

			require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
		})
	}
}
