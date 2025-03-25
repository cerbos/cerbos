// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerbos/cloud-api/bundle"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/private/engine"
	"github.com/cerbos/cerbos/private/verify"
)

func TestFiles(t *testing.T) {
	results, err := verify.Files(t.Context(), os.DirFS(test.PathToDir(t, "store")), nil)
	require.NoError(t, err)

	require.Equal(t, results.Summary.OverallResult, policyv1.TestResults_RESULT_PASSED)
}

func TestBundle(t *testing.T) {
	params := engine.BundleParams{
		BundlePath:    filepath.Join(test.PathToDir(t, filepath.Join("bundle", fmt.Sprintf("v%d", bundle.Version1))), "bundle_unencrypted.crbp"),
		BundleVersion: engine.BundleVersion1,
		TempDir:       t.TempDir(),
	}

	ctx, cancelFn := context.WithCancel(t.Context())
	t.Cleanup(cancelFn)

	results, err := verify.Bundle(ctx, params, test.PathToDir(t, "store"))
	require.NoError(t, err)
	require.Equal(t, policyv1.TestResults_RESULT_PASSED, results.Summary.OverallResult)
}
