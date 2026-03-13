// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cloud-api/bundle"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

const (
	legacyBundleName    = "bundle.crbp"
	ruleTableBundleName = "bundle.crrts"
)

func TestLocalSource(t *testing.T) {
	tctx := mkTestCtx(t, bundle.Version1, bundlev2.BundleType_BUNDLE_TYPE_LEGACY)
	lsv1 := mkLocalSource(t, tctx)
	t.Run("v1", func(t *testing.T) {
		mb, err := os.ReadFile(filepath.Join(tctx.rootDir, "manifest.json"))
		require.NoError(t, err)

		manifest := &bundlev1.Manifest{}
		require.NoError(t, protojson.Unmarshal(mb, manifest))

		t.Run("original", runLocalSourceTests(lsv1, tctx.bundleType, manifest.PolicyIndex, manifest.Schemas))
		require.NoError(t, lsv1.Reload(t.Context()), "Failed to reload local source")
		t.Run("reloaded", runLocalSourceTests(lsv1, tctx.bundleType, manifest.PolicyIndex, manifest.Schemas))

		t.Run("repoStats", runRepoStatsTest(lsv1, storage.RepoStats{
			PolicyCount: map[policy.Kind]int{
				policy.PrincipalKind:  11,
				policy.ResourceKind:   30,
				policy.RolePolicyKind: 8,
			},
			ConditionCount: map[policy.Kind]int{
				policy.PrincipalKind:  10,
				policy.ResourceKind:   62,
				policy.RolePolicyKind: 2,
			},
			RuleCount: map[policy.Kind]int{
				policy.PrincipalKind:  43,
				policy.ResourceKind:   152,
				policy.RolePolicyKind: 11,
			},
			MaxConditionCount: map[policy.Kind]int{
				policy.PrincipalKind:  3,
				policy.ResourceKind:   7,
				policy.RolePolicyKind: 1,
			},
			MaxRuleCount: map[policy.Kind]int{
				policy.PrincipalKind:  11,
				policy.ResourceKind:   17,
				policy.RolePolicyKind: 2,
			},
			AvgConditionCount: map[policy.Kind]float64{
				policy.PrincipalKind:  0.9090909090909091,
				policy.ResourceKind:   2.066666666666667,
				policy.RolePolicyKind: 0.25,
			},
			AvgRuleCount: map[policy.Kind]float64{
				policy.PrincipalKind:  3.909090909090909,
				policy.ResourceKind:   5.066666666666666,
				policy.RolePolicyKind: 1.375,
			},
			DistinctActionCount:   44,
			DistinctResourceCount: 18,
			SchemaCount:           3,
			HasOutput:             true,
			HasScopedPolicies:     true,
		}))
	})

	tctx = mkTestCtx(t, bundle.Version2, bundlev2.BundleType_BUNDLE_TYPE_LEGACY)
	lsv2 := mkLocalSource(t, tctx)
	t.Run("v2", func(t *testing.T) {
		mb, err := os.ReadFile(filepath.Join(tctx.rootDir, "manifest.json"))
		require.NoError(t, err)

		manifest := &bundlev2.Manifest{}
		require.NoError(t, protojson.Unmarshal(mb, manifest))

		t.Run("original", runLocalSourceTests(lsv2, tctx.bundleType, manifest.PolicyIndex, manifest.Schemas))
		require.NoError(t, lsv2.Reload(t.Context()), "Failed to reload local source")
		t.Run("reloaded", runLocalSourceTests(lsv2, tctx.bundleType, manifest.PolicyIndex, manifest.Schemas))

		t.Run("repoStats", runRepoStatsTest(lsv2, storage.RepoStats{
			PolicyCount: map[policy.Kind]int{
				policy.PrincipalKind:  11,
				policy.ResourceKind:   30,
				policy.RolePolicyKind: 8,
			},
			ConditionCount: map[policy.Kind]int{
				policy.PrincipalKind:  10,
				policy.ResourceKind:   62,
				policy.RolePolicyKind: 2,
			},
			RuleCount: map[policy.Kind]int{
				policy.PrincipalKind:  43,
				policy.ResourceKind:   152,
				policy.RolePolicyKind: 11,
			},
			MaxConditionCount: map[policy.Kind]int{
				policy.PrincipalKind:  3,
				policy.ResourceKind:   7,
				policy.RolePolicyKind: 1,
			},
			MaxRuleCount: map[policy.Kind]int{
				policy.PrincipalKind:  11,
				policy.ResourceKind:   17,
				policy.RolePolicyKind: 2,
			},
			AvgConditionCount: map[policy.Kind]float64{
				policy.PrincipalKind:  0.9090909090909091,
				policy.ResourceKind:   2.066666666666667,
				policy.RolePolicyKind: 0.25,
			},
			AvgRuleCount: map[policy.Kind]float64{
				policy.PrincipalKind:  3.909090909090909,
				policy.ResourceKind:   5.066666666666666,
				policy.RolePolicyKind: 1.375,
			},
			DistinctActionCount:   44,
			DistinctResourceCount: 18,
			SchemaCount:           3,
			HasOutput:             true,
			HasScopedPolicies:     true,
		}))
	})

	tctx = mkTestCtx(t, bundle.Version2, bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE)
	lsrt := mkLocalSource(t, tctx)
	t.Run("ruleTable", func(t *testing.T) {
		mb, err := os.ReadFile(filepath.Join(tctx.rootDir, "manifest.json"))
		require.NoError(t, err)

		manifest := &bundlev2.Manifest{}
		require.NoError(t, protojson.Unmarshal(mb, manifest))

		t.Run("original", runLocalSourceTests(lsrt, tctx.bundleType, manifest.PolicyIndex, manifest.Schemas))
		require.NoError(t, lsv2.Reload(t.Context()), "Failed to reload local source")
		t.Run("reloaded", runLocalSourceTests(lsrt, tctx.bundleType, manifest.PolicyIndex, manifest.Schemas))

		t.Run("repoStats", runRepoStatsTest(lsrt, storage.RepoStats{
			PolicyCount: map[policy.Kind]int{
				policy.PrincipalKind:  11,
				policy.ResourceKind:   30,
				policy.RolePolicyKind: 8,
			},
			ConditionCount: map[policy.Kind]int{
				policy.PrincipalKind:  4,
				policy.ResourceKind:   35,
				policy.RolePolicyKind: 2,
			},
			RuleCount: map[policy.Kind]int{
				policy.PrincipalKind:  20,
				policy.ResourceKind:   77,
				policy.RolePolicyKind: 9,
			},
			MaxConditionCount: map[policy.Kind]int{
				policy.PrincipalKind:  2,
				policy.ResourceKind:   5,
				policy.RolePolicyKind: 1,
			},
			MaxRuleCount: map[policy.Kind]int{
				policy.PrincipalKind:  6,
				policy.ResourceKind:   11,
				policy.RolePolicyKind: 2,
			},
			AvgConditionCount: map[policy.Kind]float64{
				policy.PrincipalKind:  0.36363636363636365,
				policy.ResourceKind:   1.1666666666666667,
				policy.RolePolicyKind: 0.25,
			},
			AvgRuleCount: map[policy.Kind]float64{
				policy.PrincipalKind:  1.8181818181818181,
				policy.ResourceKind:   2.566666666666667,
				policy.RolePolicyKind: 1.125,
			},
			DistinctActionCount:   44,
			DistinctResourceCount: 18,
			SchemaCount:           3,
			HasOutput:             true,
			HasScopedPolicies:     true,
		}))
	})
}

func runLocalSourceTests(have *hub.LocalSource, bundleType bundlev2.BundleType, policyIndex map[string]string, schemas []string) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("listPolicyIDs", func(t *testing.T) {
			havePolicies, err := have.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
			require.NoError(t, err)
			require.Len(t, havePolicies, len(policyIndex))

			for _, p := range havePolicies {
				require.Contains(t, policyIndex, namer.FQNFromPolicyKey(p), "Policy %q is not expected", p)
			}
		})

		t.Run("inspectPolicies", func(t *testing.T) {
			if bundleType == bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE {
				t.Skip()
			}

			results, err := have.InspectPolicies(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
			require.NoError(t, err)

			for policyKey, h := range results {
				mID := namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(policyKey))
				ps, err := have.GetFirstMatch(t.Context(), []namer.ModuleID{mID})
				require.NoError(t, err)

				expected := policy.ListPolicySetActions(ps)
				require.ElementsMatch(t, expected, h.Actions)
			}
		})

		t.Run("listSchemaIDs", func(t *testing.T) {
			haveSchemas, err := have.ListSchemaIDs(t.Context())
			require.NoError(t, err)
			require.Len(t, haveSchemas, len(schemas))

			for _, s := range haveSchemas {
				require.Contains(t, schemas, s)
			}
		})

		t.Run("getFirstMatch", func(t *testing.T) {
			if bundleType == bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE {
				t.Skip()
			}
			blahMod := namer.GenModuleIDFromFQN("blah")

			t.Run("existing", func(t *testing.T) {
				for fqn := range policyIndex {
					modID := namer.GenModuleIDFromFQN(fqn)
					havePolicy, err := have.GetFirstMatch(t.Context(), []namer.ModuleID{blahMod, modID})
					require.NoError(t, err, "Failed to get policy set for %q", fqn)
					require.NotNil(t, havePolicy, "Policy set %q is nil", fqn)
					require.Equal(t, havePolicy.Fqn, fqn, "FQN mismatch for policy set %q", fqn)
				}
			})

			t.Run("nonExisting", func(t *testing.T) {
				havePolicy, err := have.GetFirstMatch(t.Context(), []namer.ModuleID{blahMod})
				require.NoError(t, err)
				require.Nil(t, havePolicy)
			})
		})

		t.Run("loadSchema", func(t *testing.T) {
			t.Run("existing", func(t *testing.T) {
				for _, path := range schemas {
					haveSchema, err := have.LoadSchema(t.Context(), path)
					require.NoError(t, err, "Failed to get schema %q", path)
					t.Cleanup(func() { _ = haveSchema.Close() })

					require.NotNil(t, haveSchema, "Schema %q is nil", path)
				}
			})

			t.Run("nonExisting", func(t *testing.T) {
				_, err := have.LoadSchema(t.Context(), "blah")
				require.Error(t, err)
			})
		})
	}
}

func runRepoStatsTest(ls *hub.LocalSource, wantStats storage.RepoStats) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()

		haveStats := ls.RepoStats(t.Context())

		require.Empty(t,
			cmp.Diff(
				wantStats,
				haveStats,
				protocmp.Transform(),
				cmpopts.EquateApprox(0.0001, 0),
			),
		)
	}
}

type testCtx struct {
	rootDir    string
	scratchDir string
	bundlePath string
	version    bundle.Version
	bundleType bundlev2.BundleType
}

func mkTestCtx(t *testing.T, version bundle.Version, bundleType bundlev2.BundleType) testCtx {
	t.Helper()

	tempDir := t.TempDir()
	scratchDir := filepath.Join(tempDir, "scratch")
	require.NoError(t, os.MkdirAll(scratchDir, 0o774))

	suffix := "legacy"
	if bundleType == bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE {
		suffix = "ruletable"
	}

	rootDir := test.PathToDir(t, filepath.Join("bundle", fmt.Sprintf("v%d_%s", version, suffix)))
	bundlePath := filepath.Join(rootDir, legacyBundleName)
	if bundleType == bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE {
		bundlePath = filepath.Join(rootDir, ruleTableBundleName)
	}
	return testCtx{
		rootDir:    rootDir,
		bundlePath: bundlePath,
		scratchDir: scratchDir,
		version:    version,
		bundleType: bundleType,
	}
}

func mkLocalSource(t *testing.T, tctx testCtx) *hub.LocalSource {
	t.Helper()

	params := hub.LocalParams{
		BundlePath:    tctx.bundlePath,
		BundleVersion: tctx.version,
		TempDir:       tctx.scratchDir,
	}

	switch tctx.version {
	case bundle.Version1:
		params.SecretKey = loadSecretKey(t, tctx)
	case bundle.Version2:
		params.EncryptionKey = loadEncryptionKey(t, tctx)
	default:
	}

	ls, err := hub.NewLocalSource(t.Context(), params)
	require.NoError(t, err, "Failed to create local source")
	t.Cleanup(func() {
		require.NoError(t, ls.Close(), "Failed to close local source")
	})

	return ls
}

func loadSecretKey(t *testing.T, tCtx testCtx) string {
	t.Helper()

	keyBytes, err := os.ReadFile(filepath.Join(tCtx.rootDir, "secret_key.txt"))
	require.NoError(t, err, "Failed to read secret key")

	return string(bytes.TrimSpace(keyBytes))
}

func loadEncryptionKey(t *testing.T, tCtx testCtx) []byte {
	t.Helper()

	keyBytes, err := os.ReadFile(filepath.Join(tCtx.rootDir, "encryption_key.txt"))
	require.NoError(t, err, "Failed to read encryption key")

	encryptionKey, err := hex.DecodeString(string(keyBytes))
	require.NoError(t, err, "Failed to decode encryption key")

	return encryptionKey
}
