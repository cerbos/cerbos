// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
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

	conf := map[string]any{
		"storage": map[string]any{
			"driver": "overlay",
			"overlay": map[string]any{
				"baseDriver":        "blob",
				"fallbackDriver":    "disk",
				"failoverThreshold": 3,
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
}

func TestFailover(t *testing.T) {
	failoverThreshold := 3

	t.Run("failover not triggered when consecutive failures below threshold", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		basePolicyLoader := new(MockPolicyLoader)
		basePolicyLoader.On("GetPolicySet", ctx, mock.AnythingOfType("namer.ModuleID")).Return((*runtimev1.RunnablePolicySet)(nil), errors.New("base store error")).Times(2)
		basePolicyLoader.On("GetPolicySet", ctx, mock.AnythingOfType("namer.ModuleID")).Return(&runtimev1.RunnablePolicySet{}, nil).Once()

		fallbackPolicyLoader := new(MockPolicyLoader)

		wrappedSourceStore := &WrappedSourceStore{
			basePolicyLoader:     basePolicyLoader,
			fallbackPolicyLoader: fallbackPolicyLoader,
			circuitBreaker: gobreaker.NewCircuitBreaker(gobreaker.Settings{
				Name: "WrappedSourceStore",
				ReadyToTrip: func(counts gobreaker.Counts) bool {
					return counts.ConsecutiveFailures > uint32(failoverThreshold)
				},
				Interval: 5 * time.Minute,
				Timeout:  0,
			}),
		}

		for i := 0; i < failoverThreshold; i++ {
			_, err := wrappedSourceStore.GetPolicySet(ctx, namer.GenModuleIDFromFQN("example"))
			if i < 2 {
				require.Error(t, err, "expected base store to return an error")
			} else {
				require.NoError(t, err, "expected base store to succeed")
			}
		}

		basePolicyLoader.AssertExpectations(t)
	})
}

type MockPolicyLoader struct {
	mock.Mock
}

func (m *MockPolicyLoader) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*runtimev1.RunnablePolicySet), args.Error(1)
}
