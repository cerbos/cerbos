// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package blob_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/test/e2e"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/stretchr/testify/require"
)

func TestBlob(t *testing.T) {
	env := make(map[string]string)

	computedEnvFn := func(ctx e2e.Ctx) map[string]string {
		seaweedEndpoint := fmt.Sprintf("seaweedfs-%s-all-in-one.%s.svc.cluster.local:8333", ctx.ContextID, ctx.Namespace())
		env["E2E_BUCKET_URL"] = blob.SeaweedFSBucketURL("cerbos", seaweedEndpoint)
		env["E2E_BUCKET_PREFIX"] = "repo/"
		env["E2E_BUCKET_USERNAME"] = "admin"
		env["E2E_BUCKET_PASSWORD"] = "passw0rd"
		return env
	}

	postSetup := func(ctx e2e.Ctx) {
		p := blob.UploadParam{
			BucketURL:    env["E2E_BUCKET_URL"],
			BucketPrefix: env["E2E_BUCKET_PREFIX"],
			Username:     env["E2E_BUCKET_USERNAME"],
			Password:     env["E2E_BUCKET_PASSWORD"],
			Directory:    filepath.Join(ctx.SourceRoot, "internal", "test", "testdata", "store"),
		}

		cctx, cancelFn := ctx.CommandTimeoutCtx()
		defer cancelFn()

		_ = blob.CopyDirToBucket(ctx, cctx, p)

		expectedCount := countExpectedPolicies(t, p.Directory)
		require.NotZero(t, expectedCount)
		ctx.ReloadStore(t)
	}

	e2e.RunSuites(t, e2e.WithContextID("blob"), e2e.WithImmutableStoreSuites(), e2e.WithPostSetup(postSetup), e2e.WithComputedEnv(computedEnvFn))
}

func countExpectedPolicies(tb testing.TB, root string) int {
	tb.Helper()

	var cnt int
	require.NoError(tb, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		name := d.Name()
		if util.IsHidden(name) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if name == schema.Directory || name == util.TestDataDirectory {
				return filepath.SkipDir
			}
			return nil
		}

		if !util.IsSupportedFileType(d.Name()) || util.IsSupportedTestFile(d.Name()) {
			return nil
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		p, _, err := policy.ReadPolicy(bytes.NewReader(b))
		if err != nil || p == nil {
			// ignore invalid policies
			return nil
		}

		if p.Disabled {
			return nil
		}

		cnt++
		return nil
	}))

	return cnt
}
