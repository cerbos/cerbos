// Copyright 2021 Zenauth Ltd.

package codegen_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/codegen"
	cerbosdevv1 "github.com/cerbos/cerbos/internal/genpb/cerbosdev/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestGenerateCode(t *testing.T) {
	testCases := test.LoadTestCases(t, "codegen")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)

			have, err := codegen.GenerateCode(tc.InputPolicy)

			if tc.WantError {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			want := loadRegoModule(t, []byte(tc.WantRego))
			compareRegoModules(t, want, have.Module)

			require.EqualValues(t, tc.WantNumConditions, len(have.Conditions))
		})
	}
}

func readTestCase(t *testing.T, data []byte) *cerbosdevv1.CodeGenTestCase {
	t.Helper()

	tc := &cerbosdevv1.CodeGenTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
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
