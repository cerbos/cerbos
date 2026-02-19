// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package blob_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/test/e2e"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlob(t *testing.T) {
	env := make(map[string]string)

	computedEnvFn := func(ctx e2e.Ctx) map[string]string {
		minioEndpoint := fmt.Sprintf("minio-%s.%s.svc.cluster.local:9000", ctx.ContextID, ctx.Namespace())
		env["E2E_BUCKET_URL"] = blob.SeaweedFSBucketURL("cerbos", minioEndpoint)
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

		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client := &http.Client{Transport: tr}

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			url := fmt.Sprintf("%s/admin/policies", ctx.HTTPAddr())

			req, err := http.NewRequest(http.MethodGet, url, nil)
			require.NoError(c, err)

			req.SetBasicAuth("cerbos", "cerbosAdmin")

			resp, err := client.Do(req)
			require.NoError(c, err)
			defer resp.Body.Close()

			require.Equal(c, http.StatusOK, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(c, err)

			var lp struct {
				PolicyIDs []string `json:"policyIds"`
			}
			require.NoError(c, json.Unmarshal(body, &lp))

			require.Equal(c, expectedCount, len(lp.PolicyIDs))
		}, 1*time.Minute, 1*time.Second)

		// Give it another 5 seconds to allow events to propagate from the store to the ruletable.
		// 5 seconds might seem excessive, but the Github CI runners are driving me up the wall so
		// I want to give this test as much chance as possible at passing.
		time.Sleep(time.Second * 30)
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
			if name == schema.Directory {
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

		p, err := policy.ReadPolicy(bytes.NewReader(b))
		if err != nil {
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
