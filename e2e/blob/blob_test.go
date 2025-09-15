// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package blob_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/test/e2e"
)

func TestBlob(t *testing.T) {
	env := make(map[string]string)

	computedEnvFn := func(ctx e2e.Ctx) map[string]string {
		minioEndpoint := fmt.Sprintf("minio-%s.%s:9000", ctx.ContextID, ctx.Namespace())
		env["E2E_BUCKET_URL"] = blob.MinioBucketURL("cerbos", minioEndpoint)
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

		// Wait for Cerbos to pick up the changes
		time.Sleep(10 * time.Second)
	}

	e2e.RunSuites(t, e2e.WithContextID("blob"), e2e.WithImmutableStoreSuites(), e2e.WithPostSetup(postSetup), e2e.WithComputedEnv(computedEnvFn))
}
