// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cloud-api/base"
	bundleapi "github.com/cerbos/cloud-api/bundle"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"

	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test/mocks"
)

const (
	legacyBundleID    = "66PXRRKTQ396OECH"
	ruleTableBundleID = "6LZ4003I1IQC8T9I"
	deploymentID      = bundleapi.DeploymentID("3LWZ3N3GFMIL")
	playgroundID      = bundleapi.PlaygroundID("A4W8GJAIZYIH")
)

func TestRemoteSource(t *testing.T) {
	t.Run("legacy", runRemoteTests(bundlev2.BundleType_BUNDLE_TYPE_LEGACY))
	t.Run("ruletable", runRemoteTests(bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE))
}

func runRemoteTests(bundleType bundlev2.BundleType) func(t *testing.T) {
	return func(t *testing.T) {
		tctx := mkTestCtx(t, bundleType)

		t.Run("WithoutAutoUpdate", func(t *testing.T) {
			conf := mkConf(t, withDisableAutoUpdate())

			t.Run("BootstrapSuccess", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)

				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, loadEncryptionKey(t, tctx), nil).Once()

				require.NoError(t, rs.Init(t.Context()), "Failed to init")
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("BootstrapFail", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)

				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return("", tctx.bundleType, nil, bundleapi.ErrBootstrapBundleResponseNotFound).Once()
				mockClient.EXPECT().GetBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, loadEncryptionKey(t, tctx), nil).Once()

				require.NoError(t, rs.Init(t.Context()), "Failed to init")
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("BootstrapAndAPIFailure", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)

				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return("", tctx.bundleType, nil, errors.New("fail")).Once()
				mockClient.EXPECT().GetBundle(mock.Anything, deploymentID).Return("", tctx.bundleType, nil, errors.New("fail")).Once()

				require.Error(t, rs.Init(t.Context()), "Expected error")
				require.False(t, rs.IsHealthy(), "Source should be unhealthy")
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.Error(c, err, "Expected error from ListPolicyIDs")
					require.ErrorIs(c, err, hub.ErrBundleNotLoaded, "Expected bundle not loaded error")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("BootstrapDisabled", func(t *testing.T) {
				config := mkConf(t, withDisableAutoUpdate(), withDisableBootstrap())
				rs, mockClient := mkRemoteSource(t, config)

				mockClient.EXPECT().GetBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, loadEncryptionKey(t, tctx), nil).Once()

				require.NoError(t, rs.Init(t.Context()), "Failed to init")
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("Reload", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)

				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, loadEncryptionKey(t, tctx), nil).Twice()

				require.NoError(t, rs.Init(t.Context()), "Failed to init")
				require.NoError(t, rs.Reload(t.Context()), "Failed to reload")
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("Playground", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, mkConf(t, withDisableAutoUpdate(), withPlayground()))

				mockClient.EXPECT().BootstrapBundle(mock.Anything, playgroundID).Return("", tctx.bundleType, nil, bundleapi.ErrBootstrappingNotSupported).Once()
				bundleName := "bundle_unencrypted.crbp"
				if tctx.bundleType == bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE {
					bundleName = "bundle_unencrypted.crrt"
				}
				mockClient.EXPECT().GetBundle(mock.Anything, playgroundID).Return(filepath.Join(tctx.rootDir, bundleName), tctx.bundleType, nil, nil).Once()

				require.NoError(t, rs.Init(t.Context()), "Failed to init")
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})
		})

		t.Run("WithAutoUpdate", func(t *testing.T) {
			conf := mkConf(t)

			type watchHandle struct {
				mockHandle *mocks.WatchHandle
				eventChan  chan bundleapi.ServerEvent
				errorChan  chan error
				callsDone  chan struct{}
			}

			mkWatchHandle := func() *watchHandle {
				mockHandle := mocks.NewWatchHandle(t)
				eventChan := make(chan bundleapi.ServerEvent)
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

			wantBundleID := legacyBundleID
			if tctx.bundleType == bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE {
				wantBundleID = ruleTableBundleID
			}

			t.Run("AuthFailure", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)

				callsDone := make(chan struct{})

				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, loadEncryptionKey(t, tctx), nil).Once()
				mockClient.EXPECT().WatchBundle(mock.Anything, deploymentID).
					Run(func(context.Context, bundleapi.Source) {
						close(callsDone)
					}).
					Return(nil, base.ErrAuthenticationFailed).
					Once()

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				waitForCallsDone(t, callsDone)

				require.Eventually(t, func() bool {
					return rs.IsHealthy() == false
				}, 60*time.Millisecond, 10*time.Millisecond, "Source should be unhealthy")

				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.Error(c, err, "Expected error from ListPolicyIDs")
					require.ErrorIs(c, err, hub.ErrBundleNotLoaded, "Expected bundle not loaded error")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("BundleRemoved", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)
				wh := mkWatchHandle()
				events := []bundleapi.ServerEvent{
					{Kind: bundleapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath, BundleType: tctx.bundleType},
					{Kind: bundleapi.ServerEventBundleRemoved},
				}

				encryptionKey := loadEncryptionKey(t, tctx)
				events[0].EncryptionKey = encryptionKey //nolint:gosec
				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, encryptionKey, nil).Once()
				mockClient.EXPECT().WatchBundle(mock.Anything, deploymentID).Return(wh.mockHandle, nil).Once()
				wh.mockHandle.EXPECT().ActiveBundleChanged(wantBundleID).Return(nil)

				wh.mockHandle.EXPECT().ActiveBundleChanged(bundleapi.BundleIDOrphaned).
					Run(func(_ string) {
						close(wh.callsDone)
					}).
					Return(nil)
				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.ErrorIs(c, err, hub.ErrBundleNotLoaded, "Failed to remove the bundle")
					require.Len(c, ids, 0, "Policy IDs must be empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("PermissionDenied", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)

				callsDone := make(chan struct{})

				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, loadEncryptionKey(t, tctx), nil).Once()
				mockClient.EXPECT().WatchBundle(mock.Anything, deploymentID).
					Run(func(context.Context, bundleapi.Source) {
						close(callsDone)
					}).
					Return(nil, bundleapi.ErrPermissionDenied).
					Once()

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				waitForCallsDone(t, callsDone)

				require.Eventually(t, func() bool {
					return rs.IsHealthy() == false
				}, 60*time.Millisecond, 10*time.Millisecond, "Source should be unhealthy")

				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.Error(c, err, "Expected error from ListPolicyIDs")
					require.ErrorIs(c, err, hub.ErrBundleNotLoaded, "Expected bundle not loaded error")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("ErrorsInEvents", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)
				wh := mkWatchHandle()

				events := []bundleapi.ServerEvent{
					{Kind: bundleapi.ServerEventError, Error: errors.New("error1")},
					{Kind: bundleapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath, BundleType: tctx.bundleType},
				}

				encryptionKey := loadEncryptionKey(t, tctx)
				events[1].EncryptionKey = encryptionKey //nolint:gosec
				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, encryptionKey, nil).Once()
				mockClient.EXPECT().WatchBundle(mock.Anything, deploymentID).Return(wh.mockHandle, nil).Twice()
				wh.mockHandle.EXPECT().ActiveBundleChanged(wantBundleID).
					Run(func(_ string) {
						close(wh.callsDone)
					}).
					Return(nil)

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("Reconnect", func(t *testing.T) {
				rs, mockClient := mkRemoteSource(t, conf)
				wh := mkWatchHandle()
				var callCount atomic.Int32
				events := []bundleapi.ServerEvent{
					{Kind: bundleapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath, BundleType: tctx.bundleType},
					{Kind: bundleapi.ServerEventReconnect, ReconnectBackoff: 100 * time.Millisecond},
				}

				encryptionKey := loadEncryptionKey(t, tctx)
				events[0].EncryptionKey = encryptionKey //nolint:gosec
				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, encryptionKey, nil).Once()

				// Reconnect error should force a reconnect, resulting in two calls to WatchBundle.
				mockClient.EXPECT().WatchBundle(mock.Anything, deploymentID).
					Run(func(context.Context, bundleapi.Source) {
						if callCount.Add(1) == 2 {
							close(wh.callsDone)
						}
					}).
					Return(wh.mockHandle, nil).
					Twice()

				wh.mockHandle.EXPECT().ActiveBundleChanged(wantBundleID).Return(nil)

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})

			t.Run("Retry", func(t *testing.T) {
				if testing.Short() {
					t.SkipNow()
				}

				rs, mockClient := mkRemoteSource(t, conf)

				var callCount atomic.Int32
				callsDone := make(chan struct{})

				mockClient.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, tctx.bundleType, loadEncryptionKey(t, tctx), nil).Once()

				// Returning an error should force the caller to retry
				mockClient.EXPECT().WatchBundle(mock.Anything, deploymentID).
					Run(func(context.Context, bundleapi.Source) {
						if callCount.Add(1) == 3 {
							close(callsDone)
						}
					}).
					Return(nil, errors.New("error"))

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				waitForCallsDone(t, callsDone)

				require.False(t, rs.IsHealthy(), "Source should be unhealthy")

				require.EventuallyWithT(t, func(c *assert.CollectT) {
					ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
					require.NoError(c, err, "Failed to call ListPolicyIDs")
					require.True(c, len(ids) > 0, "Policy IDs are empty")
				}, 50*time.Millisecond, 10*time.Millisecond)
			})
		})
	}
}

type confOption func(*hub.Conf)

func withDisableAutoUpdate() confOption {
	return func(conf *hub.Conf) {
		conf.Remote.DisableAutoUpdate = true
	}
}

func withDisableBootstrap() confOption {
	return func(conf *hub.Conf) {
		conf.Remote.DisableBootstrap = true
	}
}

func withPlayground() confOption {
	return func(conf *hub.Conf) {
		conf.Remote.DeploymentID = ""
		conf.Remote.PlaygroundID = string(playgroundID)
	}
}

func mkConf(t *testing.T, opts ...confOption) *hub.Conf {
	t.Helper()

	conf := &hub.Conf{
		CacheSize: 1024,
		Remote:    &hub.RemoteSourceConf{DeploymentID: string(deploymentID)},
	}

	for _, opt := range opts {
		opt(conf)
	}

	_ = conf.Validate()

	return conf
}

func mkRemoteSource(t *testing.T, conf *hub.Conf) (*hub.RemoteSource, *mocks.Client) {
	t.Helper()

	provider := mocks.NewClientProvider(t)

	clientConf := bundleapi.ClientConf{
		CacheDir: conf.Remote.CacheDir,
		TempDir:  conf.Remote.TempDir,
	}

	mockClient := mocks.NewClient(t)
	provider.EXPECT().Client(clientConf).Return(mockClient, nil)

	rs, err := hub.NewRemoteSourceWithHub(conf, provider)
	require.NoError(t, err, "Failed to create remote source")
	t.Cleanup(func() { _ = rs.Close() })

	return rs, mockClient
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
