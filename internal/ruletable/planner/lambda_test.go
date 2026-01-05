// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrapperDoNotPanic(t *testing.T) {
	w := (*wrapper)(nil)
	require.Nil(t, w.getArg(1).getArg(2).getListElement(3).e())
	require.Zero(t, w.getArgsLen())
	require.Empty(t, w.Function())
}
