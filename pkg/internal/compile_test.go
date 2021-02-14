package internal_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/internal"
	"github.com/charithe/menshen/pkg/policy"
)

type testCase struct {
	name  string
	input string
	want  string
}

func TestCompile(t *testing.T) {
	dr := loadDerivedRoles(t, "../testdata/store/derived_roles/derived_roles_01.yaml")
	rp := loadPolicy(t, "../testdata/store/resource_policies/policy_01.yaml")
	pp := loadPolicy(t, "../testdata/store/principal_policies/policy_01.yaml")

	pset := &policyv1.PolicySet{
		DerivedRoles:      map[string]*policyv1.DerivedRoles{"../testdata/derived_roles/derived_roles_01.yaml": dr},
		ResourcePolicies:  map[string]*policyv1.Policy{"../testdata/resource_policies/policy_01.yaml": rp},
		PrincipalPolicies: map[string]*policyv1.Policy{"../testdata/principal_policies/policy_01.yaml": pp},
	}

	result, err := internal.Compile(pset)
	require.NoError(t, err)
	require.NotNil(t, result.Compiler)

	require.Contains(t, result.Resources, "leave_request")
	require.Equal(t, "20210210", result.Resources["leave_request"].HighestVersion)
	require.Contains(t, result.Resources["leave_request"].Versions, "20210210")
	require.Equal(t, "data.paams.resource.leave_request.v20210210.effect", result.Resources["leave_request"].EffectQueryForVersion(""))
	require.Equal(t, "data.paams.resource.leave_request.v20210210.effect", result.Resources["leave_request"].EffectQueryForVersion("20210210"))

	require.Contains(t, result.Principals, "donald_duck")
	require.Equal(t, "20210210", result.Principals["donald_duck"].HighestVersion)
	require.Contains(t, result.Principals["donald_duck"].Versions, "20210210")
	require.Equal(t, "data.paams.principal.donald_duck.v20210210.effect", result.Principals["donald_duck"].EffectQueryForVersion(""))
	require.Equal(t, "data.paams.principal.donald_duck.v20210210.effect", result.Principals["donald_duck"].EffectQueryForVersion("20210210"))
}

func TestCompileDerivedRoles(t *testing.T) {
	testCases := generateTestCasesFromPath(t, "../testdata/store/derived_roles")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dr := loadDerivedRoles(t, tc.input)

			have, err := internal.CompileDerivedRoles(internal.DerivedRolesModuleName(dr), dr)
			require.NoError(t, err, "Failed to compile %s", tc.input)

			want := loadRegoModule(t, tc.want)
			compareRegoModules(t, want, have)
		})
	}
}

func TestCompilePolicy(t *testing.T) {
	testFunc := func(tc testCase) func(*testing.T) {
		return func(t *testing.T) {
			p := loadPolicy(t, tc.input)

			have, err := internal.CompilePolicy(internal.PolicyModuleName(p), p)
			require.NoError(t, err, "Failed to compile %s", tc.input)

			want := loadRegoModule(t, tc.want)
			compareRegoModules(t, want, have.Mod)
		}
	}

	t.Run("resource_policies", func(t *testing.T) {
		testCases := generateTestCasesFromPath(t, "../testdata/store/resource_policies")

		for _, tc := range testCases {
			t.Run(tc.name, testFunc(tc))
		}
	})

	t.Run("principal_policies", func(t *testing.T) {
		testCases := generateTestCasesFromPath(t, "../testdata/store/principal_policies")

		for _, tc := range testCases {
			t.Run(tc.name, testFunc(tc))
		}
	})
}

func loadDerivedRoles(t *testing.T, path string) *policyv1.DerivedRoles {
	t.Helper()
	inp := mkReadCloser(t, path)
	defer inp.Close()

	dr, err := policy.LoadDerivedRoles(inp)
	require.NoError(t, err, "Failed to load %s", path)

	return dr
}

func loadPolicy(t *testing.T, path string) *policyv1.Policy {
	t.Helper()
	inp := mkReadCloser(t, path)
	defer inp.Close()

	p, err := policy.LoadPolicy(inp)
	require.NoError(t, err, "Failed to load %s", path)

	return p
}

func generateTestCasesFromPath(t *testing.T, path string) []testCase {
	t.Helper()

	entries, err := filepath.Glob(filepath.Join(path, "*.yaml"))
	require.NoError(t, err)

	var testCases []testCase

	for _, entry := range entries {
		testName := strings.TrimSuffix(filepath.Base(entry), filepath.Ext(entry))
		companion := fmt.Sprintf("%s.rego", strings.TrimSuffix(entry, filepath.Ext(entry)))

		if _, err := os.Stat(companion); os.IsNotExist(err) {
			t.Logf("Failed to find companion to %s: [%s]", entry, companion)
			continue
		}

		testCases = append(testCases, testCase{
			name:  testName,
			input: entry,
			want:  companion,
		})
	}

	return testCases
}

func mkReadCloser(t *testing.T, file string) io.ReadCloser {
	t.Helper()

	f, err := os.Open(file)
	require.NoError(t, err, "Failed to open file %s", file)

	return f
}

func loadRegoModule(t *testing.T, fileName string) *ast.Module {
	t.Helper()

	contents, err := ioutil.ReadFile(fileName)
	require.NoError(t, err, "Failed to read file %s", fileName)

	m, err := ast.ParseModule(fileName, string(contents))
	require.NoError(t, err, "Failed to parse %s", fileName)

	return m
}

func compareRegoModules(t *testing.T, want, have *ast.Module) {
	t.Helper()

	if want.Compare(have) != 0 {
		wantF := format.MustAst(want)
		haveF := format.MustAst(have)
		t.Errorf("%s", cmp.Diff(wantF, haveF))
		//	t.Errorf("Rego code does not match:\nWant:\n %s\n\nHave:\n %s\n", string(wantF), string(haveF))
	}
}
