// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/private/verify"
)

func TestFiles(t *testing.T) {
	results, err := verify.Files(t.Context(), os.DirFS(test.PathToDir(t, "store")), nil, true)
	require.NoError(t, err)

	require.Equal(t, results.Summary.OverallResult, policyv1.TestResults_RESULT_PASSED)
}
