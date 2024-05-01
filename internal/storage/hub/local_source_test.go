// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

const bundleName = "bundle.crbp"

func TestLocalSource(t *testing.T) {
	bundlePath, tempDir := prepareTestInputs(t)
	manifest := loadManifest(t)
	key := loadKey(t)

	ls, err := hub.NewLocalSource(hub.LocalParams{
		BundlePath: bundlePath,
		TempDir:    tempDir,
		SecretKey:  key,
	})
	require.NoError(t, err, "Failed to create local source")
	t.Cleanup(func() {
		require.NoError(t, ls.Close(), "Failed to close local source")
	})

	t.Run("original", runTests(ls, manifest))

	require.NoError(t, ls.Reload(context.Background()), "Failed to reload local source")
	t.Run("reloaded", runTests(ls, manifest))
}

func runTests(have *hub.LocalSource, manifest *bundlev1.Manifest) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("listPolicyIDs", func(t *testing.T) {
			havePolicies, err := have.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
			require.NoError(t, err)
			require.Len(t, havePolicies, len(manifest.PolicyIndex))

			for _, p := range havePolicies {
				require.Contains(t, manifest.PolicyIndex, p, "Policy %q is not expected", p)
			}
		})

		t.Run("inspectPolicies", func(t *testing.T) {
			results, err := have.InspectPolicies(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
			require.NoError(t, err)

			for policyKey, h := range results {
				mID := namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(policyKey))
				ps, err := have.GetFirstMatch(context.Background(), []namer.ModuleID{mID})
				require.NoError(t, err)

				expected := policy.ListPolicySetActions(ps)
				require.ElementsMatch(t, expected, h.Actions)
			}
		})

		t.Run("listSchemaIDs", func(t *testing.T) {
			haveSchemas, err := have.ListSchemaIDs(context.Background())
			require.NoError(t, err)
			require.Len(t, haveSchemas, len(manifest.Schemas))

			for _, s := range haveSchemas {
				require.Contains(t, manifest.Schemas, s)
			}
		})

		t.Run("getFirstMatch", func(t *testing.T) {
			blahMod := namer.GenModuleIDFromFQN("blah")

			t.Run("existing", func(t *testing.T) {
				for fqn := range manifest.PolicyIndex {
					modID := namer.GenModuleIDFromFQN(fqn)
					havePolicy, err := have.GetFirstMatch(context.Background(), []namer.ModuleID{blahMod, modID})
					require.NoError(t, err, "Failed to get policy set for %q", fqn)
					require.NotNil(t, havePolicy, "Policy set %q is nil", fqn)
					require.Equal(t, havePolicy.Fqn, fqn, "FQN mismatch for policy set %q", fqn)
				}
			})

			t.Run("nonExisting", func(t *testing.T) {
				havePolicy, err := have.GetFirstMatch(context.Background(), []namer.ModuleID{blahMod})
				require.NoError(t, err)
				require.Nil(t, havePolicy)
			})
		})

		t.Run("loadSchema", func(t *testing.T) {
			t.Run("existing", func(t *testing.T) {
				for _, path := range manifest.Schemas {
					haveSchema, err := have.LoadSchema(context.Background(), path)
					require.NoError(t, err, "Failed to get schema %q", path)
					t.Cleanup(func() { _ = haveSchema.Close() })

					require.NotNil(t, haveSchema, "Schema %q is nil", path)
				}
			})

			t.Run("nonExisting", func(t *testing.T) {
				_, err := have.LoadSchema(context.Background(), "blah")
				require.Error(t, err)
			})
		})
	}
}

func prepareTestInputs(t *testing.T) (string, string) {
	t.Helper()

	tempDir := t.TempDir()
	scratchDir := filepath.Join(tempDir, "scratch")
	require.NoError(t, os.MkdirAll(scratchDir, 0o774))

	bundlePath := filepath.Join(test.PathToDir(t, "bundle"), bundleName)

	return bundlePath, scratchDir
}

func loadManifest(t *testing.T) *bundlev1.Manifest {
	t.Helper()

	dir := test.PathToDir(t, "bundle")
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)

	manifest := &bundlev1.Manifest{}
	require.NoError(t, protojson.Unmarshal(mb, manifest))

	return manifest
}

func loadKey(t *testing.T) string {
	t.Helper()

	dir := test.PathToDir(t, "bundle")
	keyBytes, err := os.ReadFile(filepath.Join(dir, "secret_key.txt"))
	require.NoError(t, err, "Failed to read secret key")

	return string(bytes.TrimSpace(keyBytes))
}
