// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk"
)

func TestDriverInstantiation(t *testing.T) {
	conf := map[string]any{
		"storage": map[string]any{
			"driver": "disk",
			"disk": map[string]any{
				"directory": t.TempDir(),
			},
		},
	}

	require.NoError(t, config.LoadMap(conf))

	ctx, cancelFunc := context.WithCancel(t.Context())
	defer cancelFunc()

	store, err := storage.New(ctx)
	require.NoError(t, err)
	require.Equal(t, disk.DriverName, store.Driver())
}
