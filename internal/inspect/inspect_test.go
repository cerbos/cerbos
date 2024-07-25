// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
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
			require.NotNil(t, testCase.Expected)
			t.Run("Policies", func(t *testing.T) {
				if testCase.SkipPolicies {
					t.Skip()
				}

				pl := mkPolicyLoader(t, testCase.Inputs)
				ins := inspect.Policies()
				for _, p := range testCase.Inputs {
					require.NoError(t, ins.Inspect(p))
				}

				have, err := ins.Results(ctx, pl.LoadPolicy)
				require.NoError(t, err)
				require.NotNil(t, testCase.Expected.Policies)
				require.Empty(t, cmp.Diff(testCase.Expected.Policies, have, protocmp.Transform()))
				require.ElementsMatch(t, testCase.Expected.MissingPolicies, pl.missing, "expected missing policies")
			})

			t.Run("PolicySets", func(t *testing.T) {
				if testCase.SkipPolicySets {
					t.Skip()
				}

				dir := t.TempDir()
				for _, p := range testCase.Inputs {
					f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.%s", namer.PolicyKey(p), "yaml")))
					require.NoError(t, err)
					require.NoError(t, policy.WritePolicy(f, p))
				}

				idx, err := index.Build(ctx, os.DirFS(dir))
				require.NoError(t, err)

				mgr := schema.NewNopManager()
				ins := inspect.PolicySets()
				for unit := range idx.GetAllCompilationUnits(ctx) {
					rps, err := compile.Compile(unit, mgr)
					require.NoError(t, err)

					if rps == nil {
						continue
					}

					err = ins.Inspect(rps)
					require.NoError(t, err)
				}

				have, err := ins.Results()
				require.NoError(t, err)
				require.NotNil(t, testCase.Expected.PolicySets)
				require.Empty(t, cmp.Diff(testCase.Expected.PolicySets, have, protocmp.Transform()))
			})
		})
	}
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

	return tc
}
