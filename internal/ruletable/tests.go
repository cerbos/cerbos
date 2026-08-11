// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package ruletable

import (
	"testing"

	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/stretchr/testify/require"
)

func (rt *RuleTable) MarshalAndUnmarshalIndex(tb testing.TB) {
	tb.Helper()

	data, err := rt.idx.Marshal()
	require.NoError(tb, err, "Failed to marshal index")

	rt.idx, err = index.Unmarshal(data)
	require.NoError(tb, err, "Failed to unmarshal index")
}
