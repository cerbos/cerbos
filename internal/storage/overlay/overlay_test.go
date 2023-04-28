// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/storage/disk"
)

func TestDriverInstantiation(t *testing.T) {
	ctx := context.Background()

	bucketName := "test"
	t.Setenv("AWS_ACCESS_KEY_ID", "minioadmin")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "minioadmin")

	failoverThreshold := 3

	conf := map[string]any{
		"storage": map[string]any{
			"driver": "overlay",
			"overlay": map[string]any{
				"baseDriver":        "blob",
				"fallbackDriver":    "disk",
				"failoverThreshold": failoverThreshold,
			},
			"blob": map[string]any{
				"bucket":             blob.MinioBucketURL(bucketName, blob.StartMinio(ctx, t, bucketName)),
				"workDir":            t.TempDir(),
				"updatePollInterval": "10s",
			},
			"disk": map[string]any{
				"directory": t.TempDir(),
			},
		},
	}
	require.NoError(t, config.LoadMap(conf))

	// policy loader successfully created
	t.Run("policy loader creation successful", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		store, err := storage.New(ctx)
		require.NoError(t, err, "error creating store")
		require.Equal(t, DriverName, store.Driver())

		schemaMgr, err := schema.New(ctx, store)
		require.NoError(t, err, "error creating schema manager")

		overlayStore, ok := store.(Store)
		require.True(t, ok, "store does not implement Store interface")

		_, err = overlayStore.GetOverlayPolicyLoader(ctx, schemaMgr)
		require.NoError(t, err, "error creating overlay policy loader")

		wrappedSourceStore, ok := store.(*WrappedSourceStore)
		require.True(t, ok)

		_, ok = wrappedSourceStore.baseStore.(*blob.Store)
		require.True(t, ok, "baseStore should be of type *blob.Store")

		_, ok = wrappedSourceStore.fallbackStore.(*disk.Store)
		require.True(t, ok, "baseStore should be of type *disk.Store")
	})

	// Under failoverThreshold targets base driver
	t.Run("policy loader creation successful", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()


		_, err := storage.New(ctx)
		require.NoError(t, err, "error creating store")
	})
}
