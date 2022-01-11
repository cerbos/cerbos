// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package postgres_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/test/e2e"
)

func TestBlob(t *testing.T) {
	postSetup := func(ctx e2e.Ctx) {
		//TODO(cell) Find way to share these values with Helmfile without repeating them in both places.
		minioEndpoint := fmt.Sprintf("minio-%s.%s:9000", ctx.ContextID, ctx.Namespace())
		p := blob.UploadParam{
			BucketURL:    blob.MinioBucketURL("cerbos", minioEndpoint),
			BucketPrefix: "repo/",
			Username:     "admin",
			Password:     "passw0rd",
			Directory:    filepath.Join(ctx.SourceRoot, "internal", "test", "testdata", "store"),
		}

		cctx, cancelFn := ctx.CommandTimeoutCtx()
		defer cancelFn()

		_ = blob.CopyDirToBucket(ctx, cctx, p)

		// Wait for Cerbos to pickup the changes
		time.Sleep(150 * time.Millisecond)
	}

	e2e.RunSuites(t, e2e.WithContextID("blob"), e2e.WithSuites(e2e.ChecksSuite), e2e.WithPostSetup(postSetup))
}
