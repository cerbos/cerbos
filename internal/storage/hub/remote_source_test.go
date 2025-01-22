// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cerbos/cloud-api/base"
	cloudapi "github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/credentials"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	internalhub "github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test/mocks"
)

const (
	bundleV1ID      = "h1:Agebx+guQj0D+tgRjjOfbZp9U47poVhF9tV/P03KVmc="
	bundleV2ID      = "NCX4NBNOUSOU9KHO"
	playgroundLabel = "playground/A4W8GJAIZYIH"
)

func TestRemoteSource(t *testing.T) {
	t.Run("v1", runRemoteTests(mkTestCtx(t, cloudapi.Version1)))
	t.Run("v2", runRemoteTests(mkTestCtx(t, cloudapi.Version2)))
}

func runRemoteTests(tctx testCtx) func(t *testing.T) {
	return func(t *testing.T) {
		creds := mkCredentials(t, tctx)

		t.Run("WithoutAutoUpdate", func(t *testing.T) {
			conf := mkConf(t, withDisableAutoUpdate(), withBundleVersion(tctx.version))

			t.Run("BootstrapSuccess", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)
				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().HubCredentials().Return(creds)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Once()

				case cloudapi.Version2:
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

				default:
				}

				require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("BootstrapFail", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)
				mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return("", nil, cloudapi.ErrBootstrapBundleNotFound).Once()

				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().HubCredentials().Return(creds)
					mockClient.EXPECT().GetBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Once()

				case cloudapi.Version2:
					mockClient.EXPECT().GetBundle(mock.Anything, "label").Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

				default:
				}

				require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("BootstrapAndAPIFailure", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)
				mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return("", nil, errors.New("fail")).Once()
				mockClient.EXPECT().GetBundle(mock.Anything, "label").Return("", nil, errors.New("fail")).Once()

				require.Error(t, rs.InitWithClient(context.Background(), mockClient), "Expected error")
				require.False(t, rs.IsHealthy(), "Source should be unhealthy")

				_, err = rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.Error(t, err, "Expected error from ListPolicyIDs")
				require.ErrorIs(t, err, hub.ErrBundleNotLoaded, "Exepcted bundle not loaded error")
			})

			t.Run("Reload", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)
				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().HubCredentials().Return(creds)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Twice()

				case cloudapi.Version2:
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Twice()

				default:
				}

				require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")
				require.NoError(t, rs.Reload(context.Background()), "Failed to reload")

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("Playground", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(mkConf(t, withBundleVersion(tctx.version), withDisableAutoUpdate(), withPlayground()))
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)
				mockClient.EXPECT().GetBundle(mock.Anything, playgroundLabel).Return(filepath.Join(tctx.rootDir, "bundle_unencrypted.crbp"), nil, nil).Once()

				require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})
		})

		t.Run("OfflineMode", func(t *testing.T) {
			t.Setenv("CERBOS_HUB_OFFLINE", "true")

			rs, err := hub.NewRemoteSource(mkConf(t, withBundleVersion(tctx.version)))
			require.NoError(t, err, "Failed to create remote source")
			t.Cleanup(func() { _ = rs.Close() })

			mockClient := mocks.NewCloudAPIClient(t)
			switch tctx.version {
			case cloudapi.Version1:
				mockClient.EXPECT().HubCredentials().Return(creds)
				mockClient.EXPECT().GetCachedBundle("label").Return(tctx.bundlePath, nil).Once()

			default:
			}

			switch tctx.version {
			case cloudapi.Version1:
				require.NoError(t, rs.InitWithClient(context.Background(), mockClient), "Failed to init")

			case cloudapi.Version2:
				require.ErrorIs(t, rs.InitWithClient(context.Background(), mockClient), hub.ErrOfflineModeNotAvailable)
				return

			default:
			}

			ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
			require.NoError(t, err, "Failed to call ListPolicyIDs")
			require.True(t, len(ids) > 0, "Policy IDs are empty")
		})

		t.Run("WithAutoUpdate", func(t *testing.T) {
			conf := mkConf(t, withBundleVersion(tctx.version))

			type watchHandle struct {
				mockHandle *mocks.WatchHandle
				eventChan  chan cloudapi.ServerEvent
				errorChan  chan error
				callsDone  chan struct{}
			}

			mkWatchHandle := func() *watchHandle {
				mockHandle := mocks.NewWatchHandle(t)
				eventChan := make(chan cloudapi.ServerEvent)
				errorChan := make(chan error)
				callsDone := make(chan struct{})

				mockHandle.EXPECT().ServerEvents().Return(eventChan)
				mockHandle.EXPECT().Errors().Return(errorChan)

				return &watchHandle{
					mockHandle: mockHandle,
					eventChan:  eventChan,
					errorChan:  errorChan,
					callsDone:  callsDone,
				}
			}

			t.Run("AuthFailure", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				callsDone := make(chan struct{})

				mockClient := mocks.NewCloudAPIClient(t)
				mockClient.EXPECT().WatchBundle(mock.Anything, "label").
					Run(func(_ context.Context, _ string) {
						close(callsDone)
					}).
					Return(nil, base.ErrAuthenticationFailed).
					Once()

				ctx, cancelFn := context.WithCancel(context.Background())
				t.Cleanup(cancelFn)

				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().HubCredentials().Return(creds)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Once()

				case cloudapi.Version2:
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

				default:
				}

				require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

				waitForCallsDone(t, callsDone)

				require.Eventually(t, func() bool {
					return rs.IsHealthy() == false
				}, 60*time.Millisecond, 10*time.Millisecond, "Source should be unhealthy")

				_, err = rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.Error(t, err, "Expected error from ListPolicyIDs")
				require.ErrorIs(t, err, hub.ErrBundleNotLoaded, "Expected bundle not loaded error")
			})

			t.Run("BundleRemoved", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)

				ctx, cancelFn := context.WithCancel(context.Background())
				t.Cleanup(cancelFn)

				events := []cloudapi.ServerEvent{
					{Kind: cloudapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath},
					{Kind: cloudapi.ServerEventBundleRemoved},
				}
				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Once()
					mockClient.EXPECT().HubCredentials().Return(creds)

				case cloudapi.Version2:
					encryptionKey := loadEncryptionKey(t, tctx)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, encryptionKey, nil).Once()

					events[0].EncryptionKey = encryptionKey

				default:
				}

				wh := mkWatchHandle()
				mockClient.EXPECT().WatchBundle(mock.Anything, "label").Return(wh.mockHandle, nil).Once()

				switch tctx.version {
				case cloudapi.Version1:
					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV1ID).Return(nil)

				case cloudapi.Version2:
					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV2ID).Return(nil)

				default:
				}

				wh.mockHandle.EXPECT().ActiveBundleChanged(cloudapi.BundleIDOrphaned).
					Run(func(_ string) {
						close(wh.callsDone)
					}).
					Return(nil)
				require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.ErrorIs(t, err, hub.ErrBundleNotLoaded, "Failed to remove the bundle")
				require.Len(t, ids, 0, "Policy IDs must be empty")
			})

			t.Run("ErrorsInEvents", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)

				ctx, cancelFn := context.WithCancel(context.Background())
				t.Cleanup(cancelFn)

				wh := mkWatchHandle()
				mockClient.EXPECT().WatchBundle(mock.Anything, "label").Return(wh.mockHandle, nil).Twice()

				events := []cloudapi.ServerEvent{
					{Kind: cloudapi.ServerEventError, Error: errors.New("error1")},
					{Kind: cloudapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath},
				}

				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().HubCredentials().Return(creds)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Once()

					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV1ID).
						Run(func(_ string) {
							close(wh.callsDone)
						}).
						Return(nil)

				case cloudapi.Version2:
					encryptionKey := loadEncryptionKey(t, tctx)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, encryptionKey, nil).Once()
					events[1].EncryptionKey = encryptionKey

					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV2ID).
						Run(func(_ string) {
							close(wh.callsDone)
						}).
						Return(nil)

				default:
				}

				require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("Reconnect", func(t *testing.T) {
				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)

				ctx, cancelFn := context.WithCancel(context.Background())
				t.Cleanup(cancelFn)

				wh := mkWatchHandle()

				var callCount int32
				// Reconnect error should force a reconnect, resulting in two calls to WatchBundle.
				mockClient.EXPECT().WatchBundle(mock.Anything, "label").
					Run(func(_ context.Context, _ string) {
						if atomic.AddInt32(&callCount, 1) == 2 {
							close(wh.callsDone)
						}
					}).
					Return(wh.mockHandle, nil).
					Twice()

				events := []cloudapi.ServerEvent{
					{Kind: cloudapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath},
					{Kind: cloudapi.ServerEventReconnect, ReconnectBackoff: 100 * time.Millisecond},
				}

				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().HubCredentials().Return(creds)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Once()

					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV1ID).Return(nil)

				case cloudapi.Version2:
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV2ID).Return(nil)

					events[0].EncryptionKey = loadEncryptionKey(t, tctx)

				default:
				}

				require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("Retry", func(t *testing.T) {
				if testing.Short() {
					t.SkipNow()
				}

				rs, err := hub.NewRemoteSource(conf)
				require.NoError(t, err, "Failed to create remote source")
				t.Cleanup(func() { _ = rs.Close() })

				mockClient := mocks.NewCloudAPIClient(t)

				ctx, cancelFn := context.WithCancel(context.Background())
				t.Cleanup(cancelFn)

				var callCount int32
				callsDone := make(chan struct{})

				// Returning an error should force the caller to retry
				mockClient.EXPECT().WatchBundle(mock.Anything, "label").
					Run(func(_ context.Context, _ string) {
						if atomic.AddInt32(&callCount, 1) == 3 {
							close(callsDone)
						}
					}).
					Return(nil, errors.New("error"))

				switch tctx.version {
				case cloudapi.Version1:
					mockClient.EXPECT().HubCredentials().Return(creds)
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, nil, nil).Once()

				case cloudapi.Version2:
					mockClient.EXPECT().BootstrapBundle(mock.Anything, "label").Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

				default:
				}

				require.NoError(t, rs.InitWithClient(ctx, mockClient), "Failed to init")

				waitForCallsDone(t, callsDone)

				require.False(t, rs.IsHealthy(), "Source should be unhealthy")

				ids, err := rs.ListPolicyIDs(context.Background(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})
		})
	}
}

type confOption func(*hub.Conf)

func withBundleVersion(version cloudapi.Version) confOption {
	return func(conf *hub.Conf) {
		conf.BundleVersion = version
	}
}

func withDisableAutoUpdate() confOption {
	return func(conf *hub.Conf) {
		conf.Remote.DisableAutoUpdate = true
	}
}

func withPlayground() confOption {
	return func(conf *hub.Conf) {
		conf.Remote.BundleLabel = playgroundLabel
	}
}

func mkConf(t *testing.T, opts ...confOption) *hub.Conf {
	t.Helper()

	conf := &hub.Conf{
		BundleVersion: cloudapi.Version1,
		CacheSize:     1024,
		Remote: &hub.RemoteSourceConf{
			BundleLabel: "label",
		},
	}

	for _, opt := range opts {
		opt(conf)
	}

	require.NoError(t, conf.Validate())
	return conf
}

func mkCredentials(t *testing.T, tctx testCtx) *credentials.Credentials {
	t.Helper()

	conf := &internalhub.CredentialsConf{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		PDPID:        "pdpid",
	}

	if tctx.version == cloudapi.Version1 {
		conf.WorkspaceSecret = loadSecretKey(t, tctx)
	}

	creds, err := conf.ToCredentials()
	require.NoError(t, err)

	return creds
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
