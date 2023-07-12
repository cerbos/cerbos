// Copyright 2021-2023 Zenauth Ltd.
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
			err := initFn()
			require.NoError(t, err)

			err = r.Reload(context.Background())
			require.NoError(t, err)
		}

		policies, err := store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Len(t, policies, expectedLen)

		err = addFn()
		require.NoError(t, err)

		policies, err = store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Len(t, policies, expectedLen)

		err = r.Reload(context.Background())
		require.NoError(t, err)

		policies, err = store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Greater(t, len(policies), expectedLen)

		err = deleteFn()
		require.NoError(t, err)

		err = r.Reload(context.Background())
		require.NoError(t, err)

		policies, err = store.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{})
		require.NoError(t, err)
		require.Len(t, policies, expectedLen)
	}
}
