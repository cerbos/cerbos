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
	bundleapi "github.com/cerbos/cloud-api/bundle"
	bundleapiv2 "github.com/cerbos/cloud-api/bundle/v2"
	"github.com/cerbos/cloud-api/credentials"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	internalhub "github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/test/mocks"
)

const (
	bundleV1ID      = "h1:Hdon9Em1L7cUu4dClTCYnoEvQXoJjsMocshQsadoAWk="
	bundleV2ID      = "66PXRRKTQ396OECH"
	label           = "label"
	playgroundLabel = "playground/A4W8GJAIZYIH"
	deploymentID    = bundleapiv2.DeploymentID("3LWZ3N3GFMIL")
	playgroundID    = bundleapiv2.PlaygroundID("A4W8GJAIZYIH")
)

func TestRemoteSource(t *testing.T) {
	t.Run("v1", runRemoteTests(mkTestCtx(t, bundleapi.Version1)))
	t.Run("v2", runRemoteTests(mkTestCtx(t, bundleapi.Version2)))
}

func runRemoteTests(tctx testCtx) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("WithoutAutoUpdate", func(t *testing.T) {
			conf := mkConf(t, tctx, withDisableAutoUpdate())

			t.Run("BootstrapSuccess", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)
				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Once()

				case bundleapi.Version2:
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("BootstrapFail", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return("", bundleapi.ErrBootstrapBundleNotFound).Once()
					mockClientV1.EXPECT().GetBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Once()

				case bundleapi.Version2:
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return("", nil, bundleapi.ErrBootstrapBundleNotFound).Once()
					mockClientV2.EXPECT().GetBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("BootstrapAndAPIFailure", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return("", errors.New("fail")).Once()
					mockClientV1.EXPECT().GetBundle(mock.Anything, label).Return("", errors.New("fail")).Once()

				case bundleapi.Version2:
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return("", nil, errors.New("fail")).Once()
					mockClientV2.EXPECT().GetBundle(mock.Anything, deploymentID).Return("", nil, errors.New("fail")).Once()

				default:
				}

				require.Error(t, rs.Init(t.Context()), "Expected error")
				require.False(t, rs.IsHealthy(), "Source should be unhealthy")

				_, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.Error(t, err, "Expected error from ListPolicyIDs")
				require.ErrorIs(t, err, hub.ErrBundleNotLoaded, "Exepcted bundle not loaded error")
			})

			t.Run("Reload", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Twice()

				case bundleapi.Version2:
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Twice()

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")
				require.NoError(t, rs.Reload(t.Context()), "Failed to reload")

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("Playground", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, mkConf(t, tctx, withDisableAutoUpdate(), withPlayground(tctx.version)))

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().GetBundle(mock.Anything, playgroundLabel).Return(filepath.Join(tctx.rootDir, "bundle_unencrypted.crbp"), nil).Once()

				case bundleapi.Version2:
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, playgroundID).Return("", nil, bundleapi.ErrBootstrappingNotSupported).Once()
					mockClientV2.EXPECT().GetBundle(mock.Anything, playgroundID).Return(filepath.Join(tctx.rootDir, "bundle_unencrypted.crbp"), nil, nil).Once()

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})
		})

		t.Run("OfflineMode", func(t *testing.T) {
			t.Setenv("CERBOS_HUB_OFFLINE", "true")

			rs, mockClientV1, _ := mkRemoteSource(t, tctx, mkConf(t, tctx))

			switch tctx.version {
			case bundleapi.Version1:
				mockClientV1.EXPECT().GetCachedBundle(label).Return(tctx.bundlePath, nil).Once()
				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")

			case bundleapi.Version2:
				require.ErrorIs(t, rs.Init(t.Context()), hub.ErrOfflineModeNotAvailable)

			default:
			}
		})

		t.Run("WithAutoUpdate", func(t *testing.T) {
			conf := mkConf(t, tctx)

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

			t.Run("AuthFailure", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)

				callsDone := make(chan struct{})

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Once()
					mockClientV1.EXPECT().WatchBundle(mock.Anything, label).
						Run(func(context.Context, string) {
							close(callsDone)
						}).
						Return(nil, base.ErrAuthenticationFailed).
						Once()

				case bundleapi.Version2:
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()
					mockClientV2.EXPECT().WatchBundle(mock.Anything, deploymentID).
						Run(func(context.Context, bundleapiv2.Source) {
							close(callsDone)
						}).
						Return(nil, base.ErrAuthenticationFailed).
						Once()

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				waitForCallsDone(t, callsDone)

				require.Eventually(t, func() bool {
					return rs.IsHealthy() == false
				}, 60*time.Millisecond, 10*time.Millisecond, "Source should be unhealthy")

				_, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.Error(t, err, "Expected error from ListPolicyIDs")
				require.ErrorIs(t, err, hub.ErrBundleNotLoaded, "Expected bundle not loaded error")
			})

			t.Run("BundleRemoved", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)
				wh := mkWatchHandle()
				events := []bundleapi.ServerEvent{
					{Kind: bundleapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath},
					{Kind: bundleapi.ServerEventBundleRemoved},
				}

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Once()
					mockClientV1.EXPECT().WatchBundle(mock.Anything, label).Return(wh.mockHandle, nil).Once()
					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV1ID).Return(nil)

				case bundleapi.Version2:
					encryptionKey := loadEncryptionKey(t, tctx)
					events[0].EncryptionKey = encryptionKey
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, encryptionKey, nil).Once()
					mockClientV2.EXPECT().WatchBundle(mock.Anything, deploymentID).Return(wh.mockHandle, nil).Once()
					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV2ID).Return(nil)

				default:
				}

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

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.ErrorIs(t, err, hub.ErrBundleNotLoaded, "Failed to remove the bundle")
				require.Len(t, ids, 0, "Policy IDs must be empty")
			})

			t.Run("ErrorsInEvents", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)
				wh := mkWatchHandle()

				events := []bundleapi.ServerEvent{
					{Kind: bundleapi.ServerEventError, Error: errors.New("error1")},
					{Kind: bundleapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath},
				}

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Once()
					mockClientV1.EXPECT().WatchBundle(mock.Anything, label).Return(wh.mockHandle, nil).Twice()
					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV1ID).
						Run(func(_ string) {
							close(wh.callsDone)
						}).
						Return(nil)

				case bundleapi.Version2:
					encryptionKey := loadEncryptionKey(t, tctx)
					events[1].EncryptionKey = encryptionKey
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, encryptionKey, nil).Once()
					mockClientV2.EXPECT().WatchBundle(mock.Anything, deploymentID).Return(wh.mockHandle, nil).Twice()
					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV2ID).
						Run(func(_ string) {
							close(wh.callsDone)
						}).
						Return(nil)

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("Reconnect", func(t *testing.T) {
				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)
				wh := mkWatchHandle()
				var callCount int32
				events := []bundleapi.ServerEvent{
					{Kind: bundleapi.ServerEventNewBundle, NewBundlePath: tctx.bundlePath},
					{Kind: bundleapi.ServerEventReconnect, ReconnectBackoff: 100 * time.Millisecond},
				}

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Once()

					// Reconnect error should force a reconnect, resulting in two calls to WatchBundle.
					mockClientV1.EXPECT().WatchBundle(mock.Anything, label).
						Run(func(context.Context, string) {
							if atomic.AddInt32(&callCount, 1) == 2 {
								close(wh.callsDone)
							}
						}).
						Return(wh.mockHandle, nil).
						Twice()

					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV1ID).Return(nil)

				case bundleapi.Version2:
					encryptionKey := loadEncryptionKey(t, tctx)
					events[0].EncryptionKey = encryptionKey
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, encryptionKey, nil).Once()

					// Reconnect error should force a reconnect, resulting in two calls to WatchBundle.
					mockClientV2.EXPECT().WatchBundle(mock.Anything, deploymentID).
						Run(func(context.Context, bundleapiv2.Source) {
							if atomic.AddInt32(&callCount, 1) == 2 {
								close(wh.callsDone)
							}
						}).
						Return(wh.mockHandle, nil).
						Twice()

					wh.mockHandle.EXPECT().ActiveBundleChanged(bundleV2ID).Return(nil)

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				for _, evt := range events {
					wh.eventChan <- evt
				}

				waitForCallsDone(t, wh.callsDone)

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
			})

			t.Run("Retry", func(t *testing.T) {
				if testing.Short() {
					t.SkipNow()
				}

				rs, mockClientV1, mockClientV2 := mkRemoteSource(t, tctx, conf)

				var callCount int32
				callsDone := make(chan struct{})

				switch tctx.version {
				case bundleapi.Version1:
					mockClientV1.EXPECT().BootstrapBundle(mock.Anything, label).Return(tctx.bundlePath, nil).Once()

					// Returning an error should force the caller to retry
					mockClientV1.EXPECT().WatchBundle(mock.Anything, label).
						Run(func(context.Context, string) {
							if atomic.AddInt32(&callCount, 1) == 3 {
								close(callsDone)
							}
						}).
						Return(nil, errors.New("error"))

				case bundleapi.Version2:
					mockClientV2.EXPECT().BootstrapBundle(mock.Anything, deploymentID).Return(tctx.bundlePath, loadEncryptionKey(t, tctx), nil).Once()

					// Returning an error should force the caller to retry
					mockClientV2.EXPECT().WatchBundle(mock.Anything, deploymentID).
						Run(func(context.Context, bundleapiv2.Source) {
							if atomic.AddInt32(&callCount, 1) == 3 {
								close(callsDone)
							}
						}).
						Return(nil, errors.New("error"))

				default:
				}

				require.NoError(t, rs.Init(t.Context()), "Failed to init")

				waitForCallsDone(t, callsDone)

				require.False(t, rs.IsHealthy(), "Source should be unhealthy")

				ids, err := rs.ListPolicyIDs(t.Context(), storage.ListPolicyIDsParams{IncludeDisabled: true})
				require.NoError(t, err, "Failed to call ListPolicyIDs")
				require.True(t, len(ids) > 0, "Policy IDs are empty")
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

func withPlayground(bundleVersion bundleapi.Version) confOption {
	return func(conf *hub.Conf) {
		switch bundleVersion {
		case bundleapi.Version1:
			conf.Remote.BundleLabel = playgroundLabel
		case bundleapi.Version2:
			conf.Remote.DeploymentID = ""
			conf.Remote.PlaygroundID = string(playgroundID)
		default:
		}
	}
}

func mkConf(t *testing.T, tctx testCtx, opts ...confOption) *hub.Conf {
	t.Helper()

	conf := &hub.Conf{
		CacheSize: 1024,
		Remote:    &hub.RemoteSourceConf{},
	}

	switch tctx.version {
	case bundleapi.Version1:
		conf.Remote.BundleLabel = "label"
	case bundleapi.Version2:
		conf.Remote.DeploymentID = string(deploymentID)
	default:
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

	if tctx.version == bundleapi.Version1 {
		conf.WorkspaceSecret = loadSecretKey(t, tctx)
	}

	creds, err := conf.ToCredentials()
	require.NoError(t, err)

	return creds
}

func mkRemoteSource(t *testing.T, tctx testCtx, conf *hub.Conf) (_ *hub.RemoteSource, mockClientV1 *mocks.ClientV1, mockClientV2 *mocks.ClientV2) {
	t.Helper()

	provider := mocks.NewClientProvider(t)

	clientConf := bundleapi.ClientConf{
		CacheDir: conf.Remote.CacheDir,
		TempDir:  conf.Remote.TempDir,
	}

	switch tctx.version {
	case bundleapi.Version1:
		mockClientV1 = mocks.NewClientV1(t)
		provider.EXPECT().V1(clientConf).Return(mockClientV1, nil)
		mockClientV1.EXPECT().HubCredentials().Return(mkCredentials(t, tctx)).Maybe()

	case bundleapi.Version2:
		mockClientV2 = mocks.NewClientV2(t)
		provider.EXPECT().V2(clientConf).Return(mockClientV2, nil)

	default:
	}

	rs, err := hub.NewRemoteSourceWithHub(conf, provider)
	require.NoError(t, err, "Failed to create remote source")
	t.Cleanup(func() { _ = rs.Close() })

	return rs, mockClientV1, mockClientV2
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
