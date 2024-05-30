// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rogpeppe/go-internal/txtar"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/rolepolicy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

var updateGolden = flag.Bool("updateGolden", false, "Update the golden values for the tests")

func TestCompile(t *testing.T) {
	testCases := test.LoadTestCases(t, "compile")
	schemaMgr := mkSchemaMgr(t)

	// go test -v -tags=tests ./internal/compile/... --args -updateGolden
	if *updateGolden {
		updateGoldenFiles(t, schemaMgr, testCases)
		// reload to populate with new golden values
		testCases = test.LoadTestCases(t, "compile")
	}

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc, archive := readTestCase(t, tcase)
			cu := mkCompilationUnit(t, tc.MainDef, archive)
			haveRes, haveErr := compile.Compile(cu, schemaMgr, rolepolicy.NewNopManager())
			if len(tc.WantErrors) > 0 {
				errSet := new(compile.ErrorSet)
				require.True(t, errors.As(haveErr, &errSet))
				haveErrors := errSet.Errors()
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("GOT ERR:\n%s\n", protojson.Format(haveErrors))
					}
				})

				require.Len(t, haveErrors.GetErrors(), len(tc.WantErrors))
				requireErrors(t, tc.WantErrors, haveErrors.GetErrors())

				return
			}

			require.NotNil(t, haveRes)

			if len(tc.WantVariables) > 0 {
				requireVariables(t, tc.WantVariables, haveRes)
			}

			wantRes := &runtimev1.RunnablePolicySet{}
			require.NoError(t, protojson.Unmarshal(tcase.Want["golden"], wantRes))
			require.Empty(t, cmp.Diff(wantRes, haveRes, protocmp.Transform()))
		})
	}
}

func updateGoldenFiles(t *testing.T, schemaMgr schema.Manager, testCases []test.Case) {
	t.Helper()

	for _, tcase := range testCases {
		tc, archive := readTestCase(t, tcase)
		if len(tc.WantErrors) > 0 {
			continue
		}

		cu := mkCompilationUnit(t, tc.MainDef, archive)
		res, err := compile.Compile(cu, schemaMgr, rolepolicy.NewNopManager())
		if err != nil {
			t.Fatalf("Cannot produce golden file because compiling %q returns an error: %v", tcase.SourceFile, err)
		}

		test.WriteGoldenFile(t, tcase.SourceFile+".golden", res)
	}
}

func readTestCase(t *testing.T, testCase test.Case) (*privatev1.CompileTestCase, *txtar.Archive) {
	t.Helper()

	tc := &privatev1.CompileTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(testCase.Input), tc))

	archive := txtar.Parse(testCase.Want["input"])
	return tc, archive
}

func mkCompilationUnit(t *testing.T, mainDef string, archive *txtar.Archive) *policy.CompilationUnit {
	t.Helper()

	cu := &policy.CompilationUnit{}

	for _, f := range archive.Files {
		p, sc, err := policy.ReadPolicyWithSourceContextFromReader(bytes.NewReader(f.Data))
		require.NoError(t, err, "Unexpected error from %s", f.Name)

		modID := namer.GenModuleID(p)

		if f.Name == mainDef {
			cu.ModID = modID
		}

		cu.AddDefinition(modID, policy.WithMetadata(p, f.Name, nil, f.Name, policy.SourceFile(f.Name)), sc)
	}

	return cu
}

func mkSchemaMgr(t *testing.T) schema.Manager {
	t.Helper()

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	dir := test.PathToDir(t, filepath.Join("schema", "fs"))
	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	return schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
}

func BenchmarkCompile(b *testing.B) {
	cases := make([]*policy.CompilationUnit, b.N)
	for i := 0; i < b.N; i++ {
		cases[i] = generateCompilationUnit()
	}

	schemaMgr := schema.NewNopManager()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c := cases[i]
		_, err := compile.Compile(c, schemaMgr, rolepolicy.NewNopManager())
		if err != nil {
			b.Errorf("ERROR compile error: %v", err)
		}
	}
}

func generateCompilationUnit() *policy.CompilationUnit {
	numDerivedRolesFiles := 2
	numDerivedRolesPerFile := 10

	x := rand.Intn(100000) //nolint:gosec
	resource := fmt.Sprintf("resource_%d", x)

	cu := &policy.CompilationUnit{}

	rp := test.NewResourcePolicyBuilder(resource, "default")
	for i := 0; i < numDerivedRolesFiles; i++ {
		drName := fmt.Sprintf("derived_%02d", i)
		rr := test.NewResourceRule(fmt.Sprintf("action_%d", i)).WithEffect(effectv1.Effect_EFFECT_ALLOW).WithMatchExpr(mkMatchExpr(3)...)

		dr := test.NewDerivedRolesBuilder(drName)
		for j := 0; j < numDerivedRolesPerFile; j++ {
			name := test.RandomStr(8)
			dr = dr.AddRoleWithMatch(name, mkRandomRoleNames(5), mkMatchExpr(5)...)
			rr = rr.WithDerivedRoles(name)
		}

		drPol := dr.Build()
		drID := namer.GenModuleID(drPol)
		cu.AddDefinition(drID, drPol, parser.NewEmptySourceCtx())

		rp = rp.WithDerivedRolesImports(drName).WithRules(rr.Build())
	}

	rpPol := rp.Build()
	rpID := namer.GenModuleID(rpPol)
	cu.ModID = rpID
	cu.AddDefinition(rpID, rpPol, parser.NewEmptySourceCtx())

	return cu
}

func mkMatchExpr(n int) []string {
	exprs := make([]string, n)
	for i := 0; i < n; i++ {
		exprs[i] = fmt.Sprintf("request.principal.attr.attr_%d == request.resource.attr.attr_%d", i, i)
	}

	return exprs
}

func mkRandomRoleNames(n int) []string {
	roles := make([]string, n)
	for i := 0; i < n; i++ {
		roles[i] = test.RandomStr(5)
	}

	return roles
}

func requireErrors(t *testing.T, wantErrors, haveErrors []*runtimev1.CompileErrors_Err) {
	t.Helper()

	require.Len(t, haveErrors, len(wantErrors))

	sortErrors(haveErrors)
	sortErrors(wantErrors)
	for i, want := range wantErrors {
		require.Empty(t, cmp.Diff(want, haveErrors[i], protocmp.Transform(), protocmp.IgnoreFields(&runtimev1.CompileErrors_Err{}, "context")))
	}
}

func sortErrors(errs []*runtimev1.CompileErrors_Err) {
	sort.Slice(errs, func(i, j int) bool {
		if errs[i].File == errs[j].File {
			if errs[i].Position.GetLine() == errs[j].Position.GetLine() {
				if errs[i].Position.GetColumn() == errs[j].Position.GetColumn() {
					return errs[i].GetDescription() > errs[j].GetDescription()
				}
				return errs[i].Position.GetColumn() > errs[j].Position.GetColumn()
			}

			return errs[i].Position.GetLine() > errs[j].Position.GetLine()
		}

		return errs[i].File > errs[j].File
	})
}

func requireVariables(t *testing.T, want []*privatev1.CompileTestCase_Variables, have *runtimev1.RunnablePolicySet) {
	t.Helper()

	haveVariables := make([]*privatev1.CompileTestCase_Variables, 0, len(want))

	switch set := have.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, policy := range set.PrincipalPolicy.Policies {
			haveVariables = append(haveVariables, &privatev1.CompileTestCase_Variables{
				Scope:     policy.Scope,
				Variables: variableNames(policy.OrderedVariables),
			})
		}

	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		for _, policy := range set.ResourcePolicy.Policies {
			derivedRoles := make([]*privatev1.CompileTestCase_Variables_DerivedRole, 0, len(policy.DerivedRoles))
			for name, derivedRole := range policy.DerivedRoles {
				derivedRoles = append(derivedRoles, &privatev1.CompileTestCase_Variables_DerivedRole{
					Name:      name,
					Variables: variableNames(derivedRole.OrderedVariables),
				})
			}

			haveVariables = append(haveVariables, &privatev1.CompileTestCase_Variables{
				Scope:        policy.Scope,
				Variables:    variableNames(policy.OrderedVariables),
				DerivedRoles: derivedRoles,
			})
		}
	}

	require.Empty(t, cmp.Diff(want, haveVariables, protocmp.Transform(),
		cmpopts.SortSlices(func(a, b *privatev1.CompileTestCase_Variables) bool { return a.Scope < b.Scope }),
		protocmp.SortRepeated(func(a, b *privatev1.CompileTestCase_Variables_DerivedRole) bool { return a.Name < b.Name }),
		protocmp.SortRepeated(func(a, b string) bool { return a < b }),
	))
}

func variableNames(variables []*runtimev1.Variable) []string {
	names := make([]string, len(variables))
	for i, variable := range variables {
		names[i] = variable.Name
	}
	return names
}
