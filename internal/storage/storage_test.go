// Copyright 2021-2022 Zenauth Ltd.
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
	conf := map[string]interface{}{
		"storage": map[string]interface{}{
			"driver": "disk",
			"disk": map[string]interface{}{
				"directory": t.TempDir(),
			},
		},
	}

	require.NoError(t, config.LoadMap(conf))

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	store, err := storage.New(ctx)
	require.NoError(t, err)
	require.Equal(t, disk.DriverName, store.Driver())
}
