// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestBuildIndexWithDisk(t *testing.T) {
	dir := test.PathToDir(t, "store")

	fsys, err := util.OpenDirectoryFS(dir)
	require.NoError(t, err)

	idx, err := Build(context.Background(), fsys)
	require.NoError(t, err)
	require.NotNil(t, idx)

	idxImpl, ok := idx.(*index)
	require.True(t, ok)

	defer idx.Clear() //nolint:errcheck

	t.Run("check_contents", func(t *testing.T) {
		data := idxImpl.Inspect()
		require.Len(t, data, 41)

		rp1 := filepath.Join("resource_policies", "policy_01.yaml")
		rp2 := filepath.Join("resource_policies", "policy_02.yaml")
		rp3 := filepath.Join("resource_policies", "policy_03.yaml")
		rp4 := filepath.Join("resource_policies", "policy_04.yaml")
		rp5 := filepath.Join("resource_policies", "policy_05.yaml")
		rp6 := filepath.Join("resource_policies", "policy_05_acme.yaml")
		rp7 := filepath.Join("resource_policies", "policy_05_acme.hr.yaml")
		rp8 := filepath.Join("resource_policies", "policy_05_acme.hr.uk.yaml")
		rp9 := filepath.Join("resource_policies", "policy_09.yaml")
		rp10 := filepath.Join("resource_policies", "policy_10.yaml")
		pp1 := filepath.Join("principal_policies", "policy_01.yaml")
		pp2 := filepath.Join("principal_policies", "policy_02.yaml")
		pp3 := filepath.Join("principal_policies", "policy_02_acme.yaml")
		pp4 := filepath.Join("principal_policies", "policy_02_acme.hr.yaml")
		pp5 := filepath.Join("principal_policies", "policy_03.yaml")
		pp6 := filepath.Join("principal_policies", "policy_05.yaml")
		drCommon := filepath.Join("derived_roles", "common_roles.yaml")
		dr1 := filepath.Join("derived_roles", "derived_roles_01.yaml")
		dr2 := filepath.Join("derived_roles", "derived_roles_02.yaml")
		dr3 := filepath.Join("derived_roles", "derived_roles_03.yaml")
		dr4 := filepath.Join("derived_roles", "derived_roles_04.yaml")
		ev1 := filepath.Join("export_variables", "export_variables_01.yaml")

		for _, rp := range []string{rp1, rp5, rp6, rp7, rp8} {
			require.Contains(t, data, rp)
			require.Len(t, data[rp].Dependencies, 2)
			require.Contains(t, data[rp].Dependencies, dr1)
			require.Contains(t, data[rp].Dependencies, dr2)
			require.Empty(t, data[rp].Dependents)

			require.Contains(t, data[dr1].Dependents, rp)
			require.Contains(t, data[dr2].Dependents, rp)
		}

		require.Contains(t, data, rp2)
		require.Len(t, data[rp2].Dependencies, 0)

		require.Contains(t, data, rp3)
		require.Len(t, data[rp3].Dependencies, 1)
		require.Contains(t, data[rp3].Dependencies, dr3)
		require.Empty(t, data[rp3].Dependents)

		require.Contains(t, data, rp4)
		require.Len(t, data[rp4].Dependencies, 1)
		require.Contains(t, data[rp3].Dependencies, dr3)
		require.Empty(t, data[rp3].Dependents)

		for _, pp := range []string{pp1, pp2, pp3, pp4, pp5} {
			require.Contains(t, data, pp)
			require.Empty(t, data[pp].Dependencies)
			require.Empty(t, data[pp].Dependents)
		}

		require.Contains(t, data, drCommon)
		require.Empty(t, data[drCommon].Dependencies)
		require.Len(t, data[drCommon].Dependents, 1)

		require.Contains(t, data, dr1)
		require.Empty(t, data[dr1].Dependencies)
		require.Len(t, data[dr1].Dependents, 6)

		require.Contains(t, data, dr2)
		require.Empty(t, data[dr2].Dependencies)
		require.Len(t, data[dr2].Dependents, 7)

		require.Contains(t, data, dr3)
		require.Empty(t, data[dr3].Dependencies)
		require.Len(t, data[dr3].Dependents, 1)
		require.Contains(t, data[dr3].Dependents, rp3)

		require.Contains(t, data, ev1)
		require.Empty(t, data[ev1].Dependencies)
		require.ElementsMatch(t, []string{rp9, pp6, dr4}, data[ev1].Dependents)

		for _, p := range data[ev1].Dependents {
			require.Contains(t, data, p)
			require.ElementsMatch(t, []string{ev1}, data[p].Dependencies)
		}

		require.Contains(t, data, rp10)
		require.Equal(t, []string{dr4}, data[rp10].Dependencies)
		require.Empty(t, data[rp10].Dependents)
	})

	t.Run("check_stats", func(t *testing.T) {
		stats := idx.RepoStats(context.Background())
		require.GreaterOrEqual(t, 3, stats.SchemaCount)

		for _, k := range []policy.Kind{policy.DerivedRolesKind, policy.PrincipalKind, policy.ResourceKind} {
			t.Run(k.String(), func(t *testing.T) {
				require.Greater(t, stats.PolicyCount[k], 2)
				require.Greater(t, stats.AvgConditionCount[k], float64(0.1))
				require.Greater(t, stats.AvgRuleCount[k], float64(1.0))
			})
		}

		t.Run(policy.ExportVariablesKindStr, func(t *testing.T) {
			require.GreaterOrEqual(t, stats.PolicyCount[policy.ExportVariablesKind], 1)
			require.GreaterOrEqual(t, stats.AvgRuleCount[policy.ExportVariablesKind], float64(1.0))
			require.Zero(t, stats.AvgConditionCount[policy.ExportVariablesKind])
		})
	})

	t.Run("add_empty", func(t *testing.T) {
		_, err := idx.AddOrUpdate(Entry{})
		require.ErrorIs(t, err, ErrInvalidEntry)
	})

	t.Run("add_new", func(t *testing.T) {
		rp := policy.Wrap(test.GenResourcePolicy(test.PrefixAndSuffix("x", "x")))
		path := "x.yaml"

		evt, err := idx.AddOrUpdate(Entry{File: path, Policy: rp})
		require.NoError(t, err)
		require.Equal(t, rp.ID, evt.PolicyID)
		require.Equal(t, storage.EventAddOrUpdatePolicy, evt.Kind)

		data := idxImpl.Inspect()
		require.Contains(t, data, path)
	})
}

func TestBuildIndex(t *testing.T) {
	testCases := test.LoadTestCases(t, "index")

	for _, tcase := range testCases {
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)
			fs := toFS(t, tc)

			idx, haveErr := Build(context.Background(), fs)
			switch {
			case tc.WantErrList != nil:
				errList := new(BuildError)
				require.True(t, errors.As(haveErr, &errList))
				require.Empty(t,
					cmp.Diff(tc.WantErrList, errList.IndexBuildErrors,
						protocmp.Transform(),
						protocmp.SortRepeatedFields(&runtimev1.IndexBuildErrors{},
							"disabled", "duplicate_defs", "load_failures", "missing_imports", "missing_scopes"),
						protocmp.SortRepeated(func(a, b *runtimev1.IndexBuildErrors_LoadFailure) bool {
							if a.ErrorDetails != nil && b.ErrorDetails != nil {
								if a.ErrorDetails.GetPosition().GetLine() == b.ErrorDetails.GetPosition().GetLine() {
									return a.ErrorDetails.GetPosition().GetColumn() > b.ErrorDetails.GetPosition().GetColumn()
								}
								return a.ErrorDetails.GetPosition().GetLine() > b.ErrorDetails.GetPosition().GetLine()
							}

							return a.File > b.File
						}),
						protocmp.IgnoreFields(&sourcev1.Error{}, "context"),
						protocmp.IgnoreFields(&runtimev1.IndexBuildErrors_MissingImport{}, "context"),
						cmp.Comparer(func(s1, s2 string) bool {
							return strings.ReplaceAll(s1, "\u00a0", " ") == strings.ReplaceAll(s2, "\u00a0", " ")
						}),
					),
				)
			case tc.WantErr != "":
				require.EqualError(t, haveErr, tc.WantErr)
			default:
				require.NoError(t, haveErr)
				for _, wantCU := range tc.WantCompilationUnits {
					mainModID := namer.GenModuleIDFromFQN(wantCU.MainFqn)
					cus, err := idx.GetCompilationUnits(mainModID)
					require.NoError(t, err, "Failed to load compilation unit for %q", wantCU.MainFqn)
					require.NotEmpty(t, cus, "No results for compilation unit %q", wantCU.MainFqn)

					haveCU := cus[mainModID]
					require.NotNil(t, haveCU, "Compilation unit for %q is missing", wantCU.MainFqn)

					require.Equal(t, mainModID, haveCU.ModID)
					require.Equal(t, len(wantCU.DefinitionFqns), len(haveCU.Definitions))
					for _, defFQN := range wantCU.DefinitionFqns {
						_, ok := haveCU.Definitions[namer.GenModuleIDFromFQN(defFQN)]
						require.True(t, ok, "Definition %q is missing", defFQN)
					}

					haveAncestors := haveCU.Ancestors()
					require.Equal(t, len(wantCU.AncestorFqns), len(haveAncestors))
					if len(wantCU.AncestorFqns) > 0 {
						wantAncestors := make([]namer.ModuleID, len(wantCU.AncestorFqns))
						for i, af := range wantCU.AncestorFqns {
							wantAncestors[i] = namer.GenModuleIDFromFQN(af)
						}
						require.ElementsMatch(t, wantAncestors, haveAncestors)
					}
				}
			}
		})
	}
}

func readTestCase(t *testing.T, data []byte) *privatev1.IndexBuilderTestCase {
	t.Helper()

	tc := &privatev1.IndexBuilderTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}

func toFS(t *testing.T, tc *privatev1.IndexBuilderTestCase) fs.FS {
	t.Helper()

	fs := afero.NewMemMapFs()

	for file, data := range tc.Files {
		dir := filepath.Dir(file)
		require.NoError(t, fs.MkdirAll(dir, 0o764))

		f, err := fs.Create(file)
		require.NoError(t, err)

		_, err = io.Copy(f, strings.NewReader(data))
		require.NoError(t, err)

		require.NoError(t, f.Close())
	}

	return afero.NewIOFS(fs)
}
