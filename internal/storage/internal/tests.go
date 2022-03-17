// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package internal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage"
)

const periodToWait = 4 * time.Second

type PoliciesToStoreFn func() error

func TestSuiteReloadable(store storage.ReloadableStore, watching bool, fn PoliciesToStoreFn) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		policies, err := store.ListPolicyIDs(context.Background())
		require.NoError(t, err)
		require.Len(t, policies, 0)

		err = fn()
		require.NoError(t, err)

		if watching {
			time.Sleep(periodToWait)
		} else {
			policies, err = store.ListPolicyIDs(context.Background())
			require.NoError(t, err)
			require.Len(t, policies, 0)

			err = store.Reload(context.Background())
			require.NoError(t, err)
		}

		policies, err = store.ListPolicyIDs(context.Background())
		require.NoError(t, err)
		require.NotZero(t, len(policies))
	}
}
