// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/test"
)

func TestVerify(t *testing.T) {
	results, err := Files(context.Background(), os.DirFS(test.PathToDir(t, "store")))
	require.NoError(t, err)

	require.Equal(t, results.Summary.OverallResult, policyv1.TestResults_RESULT_PASSED)
}
