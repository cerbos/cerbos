// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cloud-api/bundle"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/private/engine"
	"github.com/cerbos/cerbos/private/verify"
)

func TestFiles(t *testing.T) {
	conf, err := evaluator.GetConf()
	require.NoError(t, err)

	results, err := verify.Files(t.Context(), conf, os.DirFS(test.PathToDir(t, "store")), nil, true)
	require.NoError(t, err)

	require.Equal(t, results.Summary.OverallResult, policyv1.TestResults_RESULT_PASSED)
}

func TestBundle(t *testing.T) {
	params := engine.BundleParams{
		BundlePath:    filepath.Join(test.PathToDir(t, filepath.Join("bundle", fmt.Sprintf("v%d_legacy", bundle.Version2))), "bundle_unencrypted.crbp"),
		BundleVersion: engine.BundleVersion2,
		TempDir:       t.TempDir(),
	}

	ctx, cancelFn := context.WithCancel(t.Context())
	t.Cleanup(cancelFn)

	conf, err := evaluator.GetConf()
	require.NoError(t, err)

	results, err := verify.Bundle(ctx, conf, params, test.PathToDir(t, "store"), true)
	require.NoError(t, err)
	require.Equal(t, policyv1.TestResults_RESULT_FAILED, results.Summary.OverallResult)
}
