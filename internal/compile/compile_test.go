// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
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
			tc := readTestCase(t, tcase.Input)

			cu := mkCompilationUnit(t, tc)
			haveRes, haveErr := compile.Compile(cu, schemaMgr)
			if len(tc.WantErrors) > 0 {
				errList := new(compile.ErrorList)
				require.True(t, errors.As(haveErr, &errList))
				require.Len(t, errList.Errors, len(tc.WantErrors))

				for _, we := range tc.WantErrors {
					require.True(t, containsErr(we, *errList), "Needle not found:\nNEEDLE=[%+v]\nHAYSTACK=[%+v]\n", we, *errList)
				}

				return
			}

			require.NotNil(t, haveRes)

			wantRes := &runtimev1.RunnablePolicySet{}
			require.NoError(t, protojson.Unmarshal(tcase.Want["golden"], wantRes))
			require.Empty(t, cmp.Diff(wantRes, haveRes, protocmp.Transform()))
		})
	}
}

func updateGoldenFiles(t *testing.T, schemaMgr schema.Manager, testCases []test.Case) {
	t.Helper()

	for _, tcase := range testCases {
		tc := readTestCase(t, tcase.Input)
		if len(tc.WantErrors) > 0 {
			continue
		}

		cu := mkCompilationUnit(t, tc)
		res, err := compile.Compile(cu, schemaMgr)
		if err != nil {
			t.Fatalf("Cannot produce golden file because compiling %q returns an error: %v", tcase.SourceFile, err)
		}

		writeGoldenFile(t, tcase.SourceFile+".golden", res)
	}
}

func writeGoldenFile(t *testing.T, path string, contents proto.Message) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create %q: %v", path, err)
	}

	defer f.Close()

	_, err = f.WriteString(protojson.Format(contents))
	if err != nil {
		f.Close()
		t.Fatalf("Failed to write to %q: %v", path, err)
	}
}

func containsErr(needle *privatev1.CompileTestCase_Error, haystack compile.ErrorList) bool {
	for _, item := range haystack.Errors {
		if needle.File != item.File {
			continue
		}

		if needle.Error != item.Error {
			continue
		}

		if needle.Desc != item.Description {
			continue
		}

		return true
	}

	return false
}

func readTestCase(t *testing.T, data []byte) *privatev1.CompileTestCase {
	t.Helper()

	tc := &privatev1.CompileTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func mkCompilationUnit(t *testing.T, tc *privatev1.CompileTestCase) *policy.CompilationUnit {
	t.Helper()

	cu := &policy.CompilationUnit{}

	for fileName, pol := range tc.InputDefs {
		modID := namer.GenModuleID(pol)

		if fileName == tc.MainDef {
			cu.ModID = modID
		}

		cu.AddDefinition(modID, policy.WithMetadata(pol, fileName, nil, fileName))
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
		_, err := compile.Compile(c, schemaMgr)
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
		cu.AddDefinition(drID, drPol)

		rp = rp.WithDerivedRolesImports(drName).WithRules(rr.Build())
	}

	rpPol := rp.Build()
	rpID := namer.GenModuleID(rpPol)
	cu.ModID = rpID
	cu.AddDefinition(rpID, rpPol)

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
