// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cerbos/cerbos/internal/storage/bundle"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/test/mocks"
	cloudapi "github.com/cerbos/cloud-api/bundle"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const bundleID = "h1:EVPzJ8jAvo0+qEaXJPe8roBCAdfGAdowddMAPMkxZY8="

func TestRemoteSource(t *testing.T) {
	bundlePath := filepath.Join(test.PathToDir(t, "bundle"), "bundle.crbp")

	t.Run("WithoutAutoUpdate", func(t *testing.T) {
		t.Run("BootstrapSuccess", func(t *testing.T) {
			mockClient := mocks.NewCloudAPIClient(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(bundlePath, nil).Once()

			rs, err := bundle.NewRemoteSource(mkConf(t, true))
			require.NoError(t, err, "Failed to create remote source")
			require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

			ids, err := rs.ListPolicyIDs(context.Background(), true)
			require.NoError(t, err, "Failed to call ListPolicyIDs")
			require.True(t, len(ids) > 0, "Policy IDs are empty")
		})

		t.Run("BootstrapFail", func(t *testing.T) {
			mockClient := mocks.NewCloudAPIClient(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return("", cloudapi.ErrBootstrapBundleNotFound).Once()
			mockClient.EXPECT().GetBundle(mock.Anything, "label").Return(bundlePath, nil).Once()

			rs, err := bundle.NewRemoteSource(mkConf(t, true))
			require.NoError(t, err, "Failed to create remote source")
			require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

			ids, err := rs.ListPolicyIDs(context.Background(), true)
			require.NoError(t, err, "Failed to call ListPolicyIDs")
			require.True(t, len(ids) > 0, "Policy IDs are empty")
		})

		t.Run("BootstrapAndAPIFailure", func(t *testing.T) {
			mockClient := mocks.NewCloudAPIClient(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return("", errors.New("fail")).Once()
			mockClient.EXPECT().GetBundle(mock.Anything, "label").Return("", errors.New("fail")).Once()

			rs, err := bundle.NewRemoteSource(mkConf(t, true))
			require.NoError(t, err, "Failed to create remote source")
			require.Error(t, rs.InitWithClient(context.Background(), mockClient), "Expected error")

			require.False(t, rs.IsHealthy(), "Source should be unhealthy")

			_, err = rs.ListPolicyIDs(context.Background(), true)
			require.Error(t, err, "Expected error from ListPolicyIDs")
			require.ErrorIs(t, err, bundle.ErrBundleNotLoaded, "Exepcted bundle not loaded error")
		})

		t.Run("Reload", func(t *testing.T) {
			mockClient := mocks.NewCloudAPIClient(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(bundlePath, nil).Twice()

			rs, err := bundle.NewRemoteSource(mkConf(t, true))
			require.NoError(t, err, "Failed to create remote source")
			require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

			require.NoError(t, rs.Reload(context.Background()), "Failed to reload")

			ids, err := rs.ListPolicyIDs(context.Background(), true)
			require.NoError(t, err, "Failed to call ListPolicyIDs")
			require.True(t, len(ids) > 0, "Policy IDs are empty")
		})
	})

	t.Run("OfflineMode", func(t *testing.T) {
		t.Setenv("CERBOS_CLOUD_OFFLINE", "true")

		mockClient := mocks.NewCloudAPIClient(t)
		mockClient.EXPECT().GetCachedBundle("label").Return(bundlePath, nil).Once()

		rs, err := bundle.NewRemoteSource(mkConf(t, false))
		require.NoError(t, err, "Failed to create remote source")
		require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

		ids, err := rs.ListPolicyIDs(context.Background(), true)
		require.NoError(t, err, "Failed to call ListPolicyIDs")
		require.True(t, len(ids) > 0, "Policy IDs are empty")
	})

	t.Run("WithAutoUpdate", func(t *testing.T) {
		t.Run("AuthFailure", func(t *testing.T) {
			callsDone := make(chan struct{})

			mockClient := mocks.NewCloudAPIClient(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(bundlePath, nil).Once()
			mockClient.EXPECT().WatchBundle(mock.Anything, "label").
				Run(func(_ context.Context, _ string) {
					close(callsDone)
				}).
				Return(nil, cloudapi.ErrAuthenticationFailed).
				Once()

			rs, err := bundle.NewRemoteSource(mkConf(t, false))
			require.NoError(t, err, "Failed to create remote source")

			ctx, cancelFn := context.WithCancel(context.Background())
			t.Cleanup(cancelFn)
			require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

			waitForCallsDone(t, callsDone)

			require.Eventually(t, func() bool {
				return rs.IsHealthy() == false
			}, 60*time.Millisecond, 10*time.Millisecond, "Source should be unhealthy")

			_, err = rs.ListPolicyIDs(context.Background(), true)
			require.Error(t, err, "Expected error from ListPolicyIDs")
			require.ErrorIs(t, err, bundle.ErrBundleNotLoaded, "Exepcted bundle not loaded error")
		})

		t.Run("BundleRemoved", func(t *testing.T) {
			eventChan := make(chan cloudapi.ServerEvent)
			errorChan := make(chan error)

			callsDone := make(chan struct{})

			mockClient := mocks.NewCloudAPIClient(t)
			mockHandle := mocks.NewWatchHandle(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(bundlePath, nil).Once()
			mockClient.EXPECT().WatchBundle(mock.Anything, "label").Return(mockHandle, nil).Once()
			mockHandle.EXPECT().ServerEvents().Return(eventChan)
			mockHandle.EXPECT().Errors().Return(errorChan)
			mockHandle.EXPECT().ActiveBundleChanged(bundleID).Return(nil)
			mockHandle.EXPECT().ActiveBundleChanged(cloudapi.BundleIDOrphaned).
				Run(func(_ string) {
					close(callsDone)
				}).
				Return(nil)

			rs, err := bundle.NewRemoteSource(mkConf(t, false))
			require.NoError(t, err, "Failed to create remote source")

			ctx, cancelFn := context.WithCancel(context.Background())
			t.Cleanup(cancelFn)
			require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

			events := []cloudapi.ServerEvent{
				{Kind: cloudapi.ServerEventNewBundle, NewBundlePath: bundlePath},
				{Kind: cloudapi.ServerEventBundleRemoved},
			}

			for _, evt := range events {
				eventChan <- evt
			}
			waitForCallsDone(t, callsDone)

			ids, err := rs.ListPolicyIDs(context.Background(), true)
			require.ErrorIs(t, err, bundle.ErrBundleNotLoaded, "Failed to remove the bundle")
			require.Len(t, ids, 0, "Policy IDs must be empty")
		})

		t.Run("ErrorsInEvents", func(t *testing.T) {
			eventChan := make(chan cloudapi.ServerEvent)
			errorChan := make(chan error)

			callsDone := make(chan struct{})

			mockClient := mocks.NewCloudAPIClient(t)
			mockHandle := mocks.NewWatchHandle(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(bundlePath, nil).Once()
			mockClient.EXPECT().WatchBundle(mock.Anything, "label").Return(mockHandle, nil).Twice()
			mockHandle.EXPECT().ServerEvents().Return(eventChan)
			mockHandle.EXPECT().Errors().Return(errorChan)
			mockHandle.EXPECT().ActiveBundleChanged(bundleID).
				Run(func(_ string) {
					close(callsDone)
				}).
				Return(nil)

			rs, err := bundle.NewRemoteSource(mkConf(t, false))
			require.NoError(t, err, "Failed to create remote source")

			ctx, cancelFn := context.WithCancel(context.Background())
			t.Cleanup(cancelFn)
			require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

			events := []cloudapi.ServerEvent{
				{Kind: cloudapi.ServerEventError, Error: errors.New("error1")},
				{Kind: cloudapi.ServerEventNewBundle, NewBundlePath: bundlePath},
			}

			for _, evt := range events {
				eventChan <- evt
			}
			waitForCallsDone(t, callsDone)

			ids, err := rs.ListPolicyIDs(context.Background(), true)
			require.NoError(t, err, "Failed to call ListPolicyIDs")
			require.True(t, len(ids) > 0, "Policy IDs are empty")
		})

		t.Run("Reconnect", func(t *testing.T) {
			eventChan := make(chan cloudapi.ServerEvent)
			errorChan := make(chan error)

			var callCount int32
			callsDone := make(chan struct{})

			mockClient := mocks.NewCloudAPIClient(t)
			mockHandle := mocks.NewWatchHandle(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(bundlePath, nil).Once()
			// Reconnect error should force a reconnect, resulting in two calls to WatchBundle.
			mockClient.EXPECT().WatchBundle(mock.Anything, "label").
				Run(func(_ context.Context, _ string) {
					if atomic.AddInt32(&callCount, 1) == 2 {
						close(callsDone)
					}
				}).
				Return(mockHandle, nil).
				Twice()
			mockHandle.EXPECT().ServerEvents().Return(eventChan)
			mockHandle.EXPECT().Errors().Return(errorChan)
			mockHandle.EXPECT().ActiveBundleChanged(bundleID).Return(nil)

			rs, err := bundle.NewRemoteSource(mkConf(t, false))
			require.NoError(t, err, "Failed to create remote source")

			ctx, cancelFn := context.WithCancel(context.Background())
			t.Cleanup(cancelFn)
			require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

			events := []cloudapi.ServerEvent{
				{Kind: cloudapi.ServerEventNewBundle, NewBundlePath: bundlePath},
				{Kind: cloudapi.ServerEventReconnect, ReconnectBackoff: 100 * time.Millisecond},
			}

			for _, evt := range events {
				eventChan <- evt
			}
			waitForCallsDone(t, callsDone)

			ids, err := rs.ListPolicyIDs(context.Background(), true)
			require.NoError(t, err, "Failed to call ListPolicyIDs")
			require.True(t, len(ids) > 0, "Policy IDs are empty")
		})

		t.Run("Retry", func(t *testing.T) {
			if testing.Short() {
				t.SkipNow()
			}

			var callCount int32
			callsDone := make(chan struct{})

			mockClient := mocks.NewCloudAPIClient(t)
			mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(bundlePath, nil).Once()
			// Returning an error should force the caller to retry
			mockClient.EXPECT().WatchBundle(mock.Anything, "label").
				Run(func(_ context.Context, _ string) {
					if atomic.AddInt32(&callCount, 1) == 3 {
						close(callsDone)
					}
				}).
				Return(nil, errors.New("error"))

			rs, err := bundle.NewRemoteSource(mkConf(t, false))
			require.NoError(t, err, "Failed to create remote source")

			ctx, cancelFn := context.WithCancel(context.Background())
			t.Cleanup(cancelFn)
			require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

			waitForCallsDone(t, callsDone)

			require.False(t, rs.IsHealthy(), "Source should be unhealthy")

			ids, err := rs.ListPolicyIDs(context.Background(), true)
			require.NoError(t, err, "Failed to call ListPolicyIDs")
			require.True(t, len(ids) > 0, "Policy IDs are empty")
		})
	})
}

func mkConf(t *testing.T, disableAutoUpdate bool) *bundle.Conf {
	t.Helper()

	return &bundle.Conf{
		Credentials: bundle.CredentialsConf{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			SecretKey:    loadKey(t),
			InstanceID:   "instanceid",
		},
		Remote: &bundle.RemoteSourceConf{
			BundleLabel:       "label",
			DisableAutoUpdate: disableAutoUpdate,
		},
	}
}

func waitForCallsDone(t *testing.T, callsDone <-chan struct{}) {
	t.Helper()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-callsDone:
	case <-timer.C:
		t.Fatal("Timed out waiting for calls")
	}
}
