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
	}

	env, err := cel.NewEnv(codegen.CerbosCELLib())
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			ast, issues := env.Compile(tc.expr)
			require.NoError(t, issues.Err())

			prg, err := env.Program(ast)
			require.NoError(t, err)

			have, _, err := prg.Eval(cel.NoVars())
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, true, have.Value())
			}
		})
	}
}
