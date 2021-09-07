// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package codegen_test

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/codegen"
)

func TestCerbosLib(t *testing.T) {
	testCases := []struct {
		expr    string
		wantErr bool
	}{
		{expr: `"192.168.0.5".inIPAddrRange("192.168.0.0/24") == true`},
		{expr: `"192.169.1.5".inIPAddrRange("192.168.0.0/24") == false`},
		{expr: `"test".inIPAddrRange("192.168.0.0/24") == false`, wantErr: true},
		{expr: `"2001:0db8:0000:0000:0000:0000:1000:0000".inIPAddrRange("2001:db8::/48") == true`},
		{expr: `"3001:0fff:0000:0000:0000:0000:0000:0000".inIPAddrRange("2001:db8::/48") == false`},
		{expr: `timestamp("2021-05-01T00:00:00.000Z").timeSince() > duration("1h")`},
		{expr: `has_intersection([1,2,3],[3,5])`},
		{expr: `has_intersection([1,2,3],[4,5]) == false`},
		{expr: `has_intersection(['1','2','3'],['3','5'])`},
		{expr: `intersect([1,2,3],[2,3,5]) == [2,3]`},
		{expr: `intersect([1,2,3],[4,5]) == []`},
		{expr: `intersect(['1','2','3'],['3','5']) == ['3']`},
		{expr: `[1,2].is_subset([2,3]) == false`},
		{expr: `[1,2].is_subset([1,2])`},
		{expr: `[1,2].is_subset([1,2,3])`},
		{expr: `["1","2"].is_subset(["1","2","3"])`},
		{expr: `[1,1].is_subset([1])`},
		{expr: `[].is_subset([1])`},
		{expr: `[].except([1]) == []`},
		{expr: `[1].except([]) == [1]`},
		{expr: `[].except([]) == []`},
		{expr: `[1].except([1]) == []`},
		{expr: `[1].except([1,2,3]) == []`},
		{expr: `[1,3,5].except([2,4]) == [1,3,5]`},
		{expr: `[1,3,5].except([5,3]) == [1]`},
	}
	env, err := cel.NewEnv(codegen.CerbosCELLib())
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			is := require.New(t)
			ast, issues := env.Compile(tc.expr)
			is.NoError(issues.Err())

			prg, err := env.Program(ast)
			is.NoError(err)

			have, _, err := prg.Eval(cel.NoVars())
			if tc.wantErr {
				is.Error(err)
			} else {
				is.NoError(err)
				is.Equal(true, have.Value())
			}
		})
	}
}
