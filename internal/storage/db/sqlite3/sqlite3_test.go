// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlite3_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage/db/internal"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
)

func TestSQLite(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	store, err := sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: "file::memory:?_fk=true"})
	require.NoError(t, err)

	t.Run("check schema", func(t *testing.T) {
		internal.TestCheckSchema(ctx, t, store)
	})

	t.Run("suite", internal.TestSuite(store))
}
