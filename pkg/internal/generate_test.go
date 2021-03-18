package internal_test

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/stretchr/testify/require"

	"github.com/charithe/menshen/pkg/internal"
	"github.com/charithe/menshen/pkg/policy"
	"github.com/charithe/menshen/pkg/test"
)

func TestGenerateCode(t *testing.T) {
	testCases := test.LoadTestCases(t, "codegen")

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			p, err := policy.ReadPolicy(bytes.NewReader(tc.Input))
			require.NoError(t, err, "Failed to read policy")

			have, err := internal.GenerateCode(p)

			if _, ok := tc.Want["err"]; ok {
				require.Error(t, err)
			}

			require.NoError(t, err)

			if b, ok := tc.Want["rego"]; ok {
				want := loadRegoModule(t, b)
				compareRegoModules(t, want, have.Module)
			}

			if b, ok := tc.Want["cond"]; ok {
				want, err := strconv.Atoi(string(bytes.TrimSpace(b)))
				require.NoError(t, err)
				require.Equal(t, want, len(have.Conditions))
			}
		})
	}
}

func loadRegoModule(t *testing.T, contents []byte) *ast.Module {
	t.Helper()

	m, err := ast.ParseModule("", string(contents))
	require.NoError(t, err, "Failed to parse module")

	return m
}

func compareRegoModules(t *testing.T, want, have *ast.Module) {
	t.Helper()

	if want.Compare(have) != 0 {
		wantF := format.MustAst(want)
		haveF := format.MustAst(have)
		t.Errorf("%s", cmp.Diff(wantF, haveF))
	}
}
