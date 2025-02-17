// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerbos/cloud-api/bundle"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test"
)

const bundleName = "bundle.crbp"

func TestLocalSource(t *testing.T) {
	tctx := mkTestCtx(t, bundle.Version1)
	lsv1 := mkLocalSource(t, tctx)
	t.Run("v1", func(t *testing.T) {
		mb, err := os.ReadFile(filepath.Join(tctx.rootDir, "manifest.json"))
		require.NoError(t, err)

		manifest := &bundlev1.Manifest{}
		require.NoError(t, protojson.Unmarshal(mb, manifest))

		t.Run("original", runLocalSourceTests(lsv1, manifest.PolicyIndex, manifest.Schemas))
		require.NoError(t, lsv1.Reload(t.Context()), "Failed to reload local source")
		t.Run("reloaded", runLocalSourceTests(lsv1, manifest.PolicyIndex, manifest.Schemas))
	})

	tctx = mkTestCtx(t, bundle.Version2)
	lsv2 := mkLocalSource(t, tctx)
	t.Run("v2", func(t *testing.T) {
		mb, err := os.ReadFile(filepath.Join(tctx.rootDir, "manifest.json"))
		require.NoError(t, err)

		manifest := &bundlev2.Manifest{}
		require.NoError(t, protojson.Unmarshal(mb, manifest))

		t.Run("original", runLocalSourceTests(lsv2, manifest.PolicyIndex, manifest.Schemas))
		require.NoError(t, lsv2.Reload(t.Context()), "Failed to reload local source")
		t.Run("reloaded", runLocalSourceTests(lsv2, manifest.PolicyIndex, manifest.Schemas))
	})
}

func runLocalSourceTests(have *hub.LocalSource, policyIndex map[string]string, schemas []string) func(*testing.T) {
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

type testCtx struct {
	rootDir    string
	scratchDir string
	bundlePath string
	version    bundle.Version
}

func mkTestCtx(t *testing.T, version bundle.Version) testCtx {
	t.Helper()

	tempDir := t.TempDir()
	scratchDir := filepath.Join(tempDir, "scratch")
	require.NoError(t, os.MkdirAll(scratchDir, 0o774))

	rootDir := test.PathToDir(t, filepath.Join("bundle", fmt.Sprintf("v%d", version)))
	bundlePath := filepath.Join(rootDir, bundleName)
	return testCtx{
		rootDir:    rootDir,
		bundlePath: bundlePath,
		scratchDir: scratchDir,
		version:    version,
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

	ls, err := hub.NewLocalSource(params)
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
