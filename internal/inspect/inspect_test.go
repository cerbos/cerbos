// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/inspect"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestInspect(t *testing.T) {
	testCases := test.LoadTestCases(t, "inspect")
	ctx := context.Background()
	for _, testMetadata := range testCases {
		testCase := readTestCase(t, testMetadata.Input)
		t.Run(testMetadata.Name, func(t *testing.T) {
			inputs := testCase.Inputs
			mgr := schema.NewNopManager()
			pl := mkPolicyLoader(t, inputs)
			dir := t.TempDir()
			for _, p := range inputs {
				f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.%s", namer.PolicyKey(p), "yaml")))
				require.NoError(t, err)
				require.NoError(t, policy.WritePolicy(f, p))
			}

			t.Run("Policies", func(t *testing.T) {
				expectedPolicies := testCase.PoliciesExpectation.Policies
				expectedMissingPolicies := testCase.PoliciesExpectation.MissingPolicies

				ins := inspect.Policies()
				for _, p := range inputs {
					require.NoError(t, ins.Inspect(p))
				}

				have, err := ins.Results(ctx, pl.LoadPolicy)
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(expectedPolicies, have, protocmp.Transform()))
				require.ElementsMatch(t, expectedMissingPolicies, pl.missing, "expected missing policies")
			})

			t.Run("PolicySets", func(t *testing.T) {
				expectedPolicySets := testCase.PolicySetsExpectation.PolicySets
				expectedErrors := testCase.PolicySetsExpectation.Errors

				idx, err := index.Build(ctx, os.DirFS(dir))
				var haveIdxBuildErr *index.BuildError
				if errors.As(err, &haveIdxBuildErr) {
					require.Empty(t,
						cmp.Diff(
							expectedErrors.(*privatev1.InspectTestCase_PolicySetsExpectation_IndexBuildErrors).IndexBuildErrors,
							haveIdxBuildErr.IndexBuildErrors,
							protocmp.Transform(),
							protocmp.IgnoreFields(&sourcev1.Error{}, "context"),
						),
					)
					return
				}
				require.NoError(t, err)

				ins := inspect.PolicySets()
				for unit := range idx.GetAllCompilationUnits(ctx) {
					rps, err := compile.Compile(unit, mgr)
					var haveCompileErrSet *compile.ErrorSet
					if errors.As(err, &haveCompileErrSet) {
						require.Empty(t,
							cmp.Diff(
								compileErrorsMap(expectedErrors.(*privatev1.InspectTestCase_PolicySetsExpectation_CompileErrors_).CompileErrors.CompileErrors),
								haveCompileErrSet.CompileErrors,
								protocmp.Transform(),
								protocmp.IgnoreFields(&runtimev1.CompileErrors_Err{}, "context"),
							),
						)
						continue
					}
					require.NoError(t, err)

					if rps == nil {
						continue
					}

					require.NoError(t, ins.Inspect(rps))
				}

				if expectedErrors == nil {
					have, err := ins.Results()
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(expectedPolicySets, have, protocmp.Transform()))
				}
			})
		})
	}
}

func compileErrorsMap(compileErrors []*runtimev1.CompileErrors_Err) map[uint64]*runtimev1.CompileErrors_Err {
	m := make(map[uint64]*runtimev1.CompileErrors_Err)
	for _, compileErr := range compileErrors {
		key := util.HashStr(fmt.Sprintf("%s:%d:%d:%s", compileErr.GetFile(), compileErr.GetPosition().GetLine(), compileErr.GetPosition().GetColumn(), compileErr.GetDescription()))
		m[key] = compileErr
	}

	return m
}

func mkPolicyLoader(t *testing.T, policies []*policyv1.Policy) *policyLoader {
	t.Helper()

	policyMap := make(map[string]*policyv1.Policy)
	for _, p := range policies {
		policyMap[namer.PolicyKey(p)] = p
	}

	return &policyLoader{
		policies: policyMap,
	}
}

type policyLoader struct {
	policies map[string]*policyv1.Policy
	loaded   []string
	missing  []string
}

func (pl *policyLoader) LoadPolicy(_ context.Context, policyKey ...string) ([]*policy.Wrapper, error) {
	policies := make([]*policy.Wrapper, 0, len(policyKey))
	for _, pk := range policyKey {
		p, ok := pl.policies[pk]
		if !ok {
			pl.missing = append(pl.missing, pk)
			continue
		}

		wp := policy.Wrap(p)
		policies = append(policies, &wp)
		pl.loaded = append(pl.loaded, pk)
	}

	return policies, nil
}

func readTestCase(tb testing.TB, data []byte) *privatev1.InspectTestCase {
	tb.Helper()

	tc := &privatev1.InspectTestCase{}
	require.NoError(tb, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	if tc.PoliciesExpectation == nil {
		tc.PoliciesExpectation = &privatev1.InspectTestCase_PoliciesExpectation{}
	}

	if tc.PolicySetsExpectation == nil {
		tc.PolicySetsExpectation = &privatev1.InspectTestCase_PolicySetsExpectation{}
	}

	return tc
}
