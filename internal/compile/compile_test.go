// Copyright 2021 Zenauth Ltd.

package compile_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/compile"
	cerbosdevv1 "github.com/cerbos/cerbos/internal/genpb/cerbosdev/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestCompile(t *testing.T) {
	testCases := test.LoadTestCases(t, "compile")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)

			cu := mkCompilationUnit(t, tc)
			haveRes, haveErr := compile.Compile(cu)
			if len(tc.WantErrors) > 0 {
				errList := new(compile.ErrorList)
				require.True(t, errors.As(haveErr, errList))

				require.Len(t, *errList, len(tc.WantErrors))
				for _, err := range *errList {
					require.Contains(t, tc.WantErrors, err.Error())
				}

				return
			}

			require.NotNil(t, haveRes)
		})
	}
}

func readTestCase(t *testing.T, data []byte) *cerbosdevv1.CompileTestCase {
	t.Helper()

	tc := &cerbosdevv1.CompileTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func mkCompilationUnit(t *testing.T, tc *cerbosdevv1.CompileTestCase) *policy.CompilationUnit {
	t.Helper()

	cu := &policy.CompilationUnit{}

	for fileName, pol := range tc.InputDefs {
		modID := namer.GenModuleID(pol)

		if fileName == tc.MainDef {
			cu.ModID = modID
		}

		cu.AddDefinition(modID, policy.WithMetadata(pol, fileName, nil))

		if gp, err := codegen.GenerateRepr(pol); err == nil {
			cu.AddGenerated(modID, gp)
		}
	}

	return cu
}

func BenchmarkCompile(b *testing.B) {
	cases := make([]*policy.CompilationUnit, b.N)
	for i := 0; i < b.N; i++ {
		cases[i] = generateCompilationUnit()
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c := cases[i]
		_, err := compile.Compile(c)
		if err != nil {
			b.Errorf("ERROR compile error: %v", err)
		}
	}
}

func generateCompilationUnit() *policy.CompilationUnit {
	numDerivedRolesFiles := 10
	numDerivedRolesPerFile := 10

	x := rand.Intn(100000) //nolint:gosec
	resource := fmt.Sprintf("resource_%d", x)

	cu := &policy.CompilationUnit{}

	rp := test.NewResourcePolicyBuilder(resource, "default")
	for i := 0; i < numDerivedRolesFiles; i++ {
		drName := fmt.Sprintf("derived_%02d", i)
		rr := test.NewResourceRule(fmt.Sprintf("action_%d", i)).WithEffect(sharedv1.Effect_EFFECT_ALLOW).WithMatchExpr(mkMatchExpr(3)...)

		dr := test.NewDerivedRolesBuilder(drName)
		for j := 0; j < numDerivedRolesPerFile; j++ {
			name := test.RandomStr(8)
			dr = dr.AddRoleWithMatch(name, mkRandomRoleNames(5), mkMatchExpr(5)...)
			rr = rr.WithDerivedRoles(name)
		}

		drPol := dr.Build()

		drGen, err := codegen.GenerateRepr(drPol)
		if err != nil {
			panic(err)
		}

		drID := namer.GenModuleID(drPol)
		cu.AddDefinition(drID, drPol)
		cu.AddGenerated(drID, drGen)

		rp = rp.WithDerivedRolesImports(drName).WithRules(rr.Build())
	}

	rpPol := rp.Build()

	rpGen, err := codegen.GenerateRepr(rpPol)
	if err != nil {
		panic(err)
	}

	rpID := namer.GenModuleID(rpPol)
	cu.ModID = rpID
	cu.AddDefinition(rpID, rpPol)
	cu.AddGenerated(rpID, rpGen)

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
