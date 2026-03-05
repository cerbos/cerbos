// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceAttributeNames(t *testing.T) {
	name := "a"
	fqns := ResourceAttributeNames(name)
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
			have := ExpandAbbrev(tc.input)
			require.Equal(t, tc.want, have)
		})
	}
}
