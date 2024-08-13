// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package internal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage"
)

// MutateStoreFn points to a function which mutates the store (ex: add, delete a policy).
type MutateStoreFn func() error

func TestSuiteReloadable(store storage.Store, initFn, addFn, deleteFn MutateStoreFn) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		r, ok := store.(storage.Reloadable)
		require.True(t, ok, "Store is not reloadable")

		expectedLen := 0
		if initFn != nil {
			expectedLen = 1
			require.NoError(t, initFn())
			require.NoError(t, r.Reload(context.Background()))
		}

		policies, err := store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Len(t, policies, expectedLen)

		require.NoError(t, addFn())

		policies, err = store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Len(t, policies, expectedLen)

		require.NoError(t, r.Reload(context.Background()))

		policies, err = store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Greater(t, len(policies), expectedLen)

		require.NoError(t, deleteFn())

		require.NoError(t, r.Reload(context.Background()))

		policies, err = store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Len(t, policies, expectedLen)
	}
}
