// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/util"
	"github.com/stretchr/testify/require"
)

func TestGetCompiledExpr(t *testing.T) {
	c := util.NewRegexpCache()

	t.Run("Valid expression", func(t *testing.T) {
		expr := "^test$"

		re, err := c.GetCompiledExpr(expr)

		require.NoError(t, err, "Failed to get compiled expression from cache")
		require.NotNil(t, re, "Expected regular expression to be non-nil")
		require.Equal(t, expr, re.String(), "Expected regular expression to match input")
	})

	t.Run("Invalid expression", func(t *testing.T) {
		expr := "\\"

		_, err := c.GetCompiledExpr(expr)

		require.Error(t, err, "Expected error")
	})

	t.Run("Cached expression", func(t *testing.T) {
		expr := "^test$"

		re1, err := c.GetCompiledExpr(expr)
		require.NoError(t, err, "Failed to get compiled expression from cache")

		re2, err := c.GetCompiledExpr(expr)
		require.NoError(t, err, "Failed to get compiled expression from cache")

		require.Same(t, re1, re2, "Expected to get the same regular expression object from the cache")
	})
}
