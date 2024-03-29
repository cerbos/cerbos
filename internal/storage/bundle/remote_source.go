// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cloud-api/base"
	cloudapi "github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/credentials"
	"github.com/go-logr/zapr"
	"github.com/spf13/afero"
	"go.uber.org/zap"
)

const (
	defaultReconnectBackoff = 5 * time.Second
	noBundleInitialInterval = 60 * time.Second
	noBundleMaxInterval     = 10 * time.Minute
	noBundleMaxCount        = 10
)

var (
	_ storage.BinaryStore = (*RemoteSource)(nil)
	_ storage.Reloadable  = (*RemoteSource)(nil)
)

type CloudAPIClient interface {
	BootstrapBundle(context.Context, string) (string, error)
	GetBundle(context.Context, string) (string, error)
	WatchBundle(context.Context, string) (cloudapi.WatchHandle, error)
	GetCachedBundle(string) (string, error)
}

// RemoteSource implements a bundle store that loads bundles from a remote source.
type RemoteSource struct {
	credentials *credentials.Credentials
	log         *zap.Logger
	conf        *Conf
	bundle      *Bundle
	scratchFS   afero.Fs
	client      CloudAPIClient
	mu          sync.RWMutex
	healthy     bool
}

func NewRemoteSource(conf *Conf) (*RemoteSource, error) {
	credentials, err := conf.Credentials.ToCredentials()
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	logger := zap.L().Named("bundle").With(zap.String("label", conf.Remote.BundleLabel))
	scratchFS := afero.NewBasePathFs(afero.NewOsFs(), conf.Remote.TempDir)
	return &RemoteSource{log: logger, conf: conf, healthy: false, scratchFS: scratchFS, credentials: credentials}, nil
}

func (s *RemoteSource) Init(ctx context.Context) error {
	pdpID := util.PDPIdentifier(s.conf.Credentials.PDPID)
	s.log = s.log.With(zap.String("instance", pdpID.Instance))

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: s.conf.Remote.Connection.TLS.Authority,
	}

	caCertPath := s.conf.Remote.Connection.TLS.CACert
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return fmt.Errorf("failed to read CA cert from %q: %w", caCertPath, err)
		}

		tlsConf.RootCAs = x509.NewCertPool()
		if !tlsConf.RootCAs.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certs")
		}
	}

	clientConf := cloudapi.ClientConf{
		ClientConf: base.ClientConf{
			Logger:            zapr.NewLogger(s.log),
			PDPIdentifier:     pdpID,
			TLS:               tlsConf,
			Credentials:       s.credentials,
			APIEndpoint:       s.conf.Remote.Connection.APIEndpoint,
			BootstrapEndpoint: s.conf.Remote.Connection.BootstrapEndpoint,
			RetryWaitMin:      s.conf.Remote.Connection.MinRetryWait,
			RetryWaitMax:      s.conf.Remote.Connection.MaxRetryWait,
			RetryMaxAttempts:  int(s.conf.Remote.Connection.NumRetries),
			HeartbeatInterval: s.conf.Remote.Connection.HeartbeatInterval,
		},
		CacheDir: s.conf.Remote.CacheDir,
		TempDir:  s.conf.Remote.TempDir,
	}

	client, err := cloudapi.NewClient(clientConf)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	return s.InitWithClient(ctx, client)
}

func (s *RemoteSource) InitWithClient(ctx context.Context, client CloudAPIClient) error {
	s.client = client

	// Ideally we want to be able to automatically switch between online and offline modes.
	// That logic is complicated to implement and test in the little time we have. There are open questions
	// about expected behaviour as well. For example, is it preferable to use a stale copy from cache or fail fast?
	// So, this initial version just provides an escape hatch to manually deal with downtime by putting the PDP
	// into offline mode.
	// TODO(cell): Implement automatic online/offline mode
	if shouldWorkOffline() {
		s.log.Warn("Working in offline mode because the CERBOS_HUB_OFFLINE environment variable is set")
		return s.fetchBundleOffline()
	}

	// fail fast if the service is down
	if err := s.fetchBundle(ctx); err != nil {
		return err
	}

	if !s.conf.Remote.DisableAutoUpdate {
		eb := backoff.NewExponentialBackOff()
		eb.InitialInterval = noBundleInitialInterval
		eb.MaxElapsedTime = 0
		eb.MaxInterval = noBundleMaxInterval
		eb.Multiplier = 2
		b := backoff.WithMaxRetries(eb, noBundleMaxCount)

		go s.startWatchLoop(ctx, b)
	}

	return nil
}

func shouldWorkOffline() bool {
	v := hub.GetEnv(hub.OfflineKey)
	offline, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}

	return offline
}

func (s *RemoteSource) fetchBundle(ctx context.Context) error {
	s.log.Info("Fetching bundle")
	bdlPath, err := s.client.BootstrapBundle(ctx, s.conf.Remote.BundleLabel)
	if err == nil {
		s.log.Debug("Using bootstrap bundle")
		return s.swapBundle(bdlPath)
	}

	s.log.Warn("Failed to fetch bootstrap bundle", zap.Error(err))
	s.log.Info("Attempting to fetch bundle from the API")
	bdlPath, err = s.client.GetBundle(ctx, s.conf.Remote.BundleLabel)
	if err != nil {
		s.log.Error("Failed to fetch bundle using the API", zap.Error(err))
		metrics.Inc(ctx, metrics.BundleFetchErrorsCount())
		return fmt.Errorf("failed to fetch bundle: %w", err)
	}

	s.log.Debug("Using bundle fetched from the API")
	return s.swapBundle(bdlPath)
}

func (s *RemoteSource) fetchBundleOffline() error {
	s.log.Info("Looking for cached bundle")
	bdlPath, err := s.client.GetCachedBundle(s.conf.Remote.BundleLabel)
	if err != nil {
		s.log.Error("Failed to find cached bundle", zap.Error(err))
		return fmt.Errorf("failed to find cached bundle: %w", err)
	}

	return s.swapBundle(bdlPath)
}

func (s *RemoteSource) removeBundle(healthy bool) {
	s.mu.Lock()
	oldBundle := s.bundle
	s.bundle = nil
	s.healthy = healthy
	s.mu.Unlock()

	if oldBundle != nil {
		if err := oldBundle.Release(); err != nil {
			s.log.Warn("Failed to release old bundle", zap.Error(err))
		}
	}
}

func (s *RemoteSource) swapBundle(bundlePath string) error {
	s.log.Debug("Swapping bundle", zap.String("path", bundlePath))

	bundle, err := Open(OpenOpts{
		Source:      "remote",
		BundlePath:  bundlePath,
		ScratchFS:   s.scratchFS,
		Credentials: s.credentials,
		CacheSize:   s.conf.CacheSize,
	})
	if err != nil {
		s.log.Error("Failed to open bundle", zap.Error(err))
		return fmt.Errorf("failed to open bundle: %w", err)
	}

	s.mu.Lock()
	oldBundle := s.bundle
	s.bundle = bundle
	s.healthy = true
	s.mu.Unlock()

	if oldBundle != nil {
		if err := oldBundle.Release(); err != nil {
			s.log.Warn("Failed to release old bundle", zap.Error(err))
		}
	}

	metrics.Inc(context.Background(), metrics.BundleStoreUpdatesCount())

	return nil
}

func (s *RemoteSource) activeBundleVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil || s.bundle.manifest == nil || s.bundle.manifest.Meta == nil {
		return cloudapi.BundleIDUnknown
	}

	return s.bundle.manifest.Meta.Identifier
}

func (s *RemoteSource) startWatchLoop(ctx context.Context, noBundleBackoff backoff.BackOff) {
	s.log.Info("Starting watch")
	wait, err := s.startWatch(ctx)
	if err != nil {
		if !errors.Is(err, cloudapi.ErrBundleNotFound) {
			s.log.Warn("Terminating bundle watch", zap.Error(err))
			metrics.Add(ctx, metrics.HubConnected(), -1)
			return
		}

		metrics.Inc(ctx, metrics.BundleNotFoundErrorsCount())
		wait = noBundleBackoff.NextBackOff()
		if wait == backoff.Stop {
			s.log.Warn("Giving up waiting for the bundle to re-appear: terminating bundle watch")
			s.log.Info("Restart this instance to re-establish connection to Cerbos Hub")
			metrics.Add(ctx, metrics.HubConnected(), -1)
			return
		}
	}

	// reset backoff if the last call succeeded
	if err == nil {
		noBundleBackoff.Reset()
	}

	if wait <= 0 {
		wait = defaultReconnectBackoff
	}

	s.log.Info(fmt.Sprintf("Restarting watch in %s", wait))
	timer := time.NewTicker(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		s.log.Info("Terminating bundle watch due to context cancellation")
		return
	case <-timer.C:
		go s.startWatchLoop(ctx, noBundleBackoff)
	}
}

func incEventMetric(event string) {
	metrics.Inc(context.Background(), metrics.BundleStoreRemoteEventsCount(), metrics.RemoteEventKey(event))
}

func (s *RemoteSource) startWatch(ctx context.Context) (time.Duration, error) {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0 // Retry indefinitely
	backoffCtx := backoff.WithContext(b, ctx)

	var watchHandle cloudapi.WatchHandle
	op := func() (err error) {
		watchHandle, err = s.client.WatchBundle(ctx, s.conf.Remote.BundleLabel)
		if err != nil {
			s.mu.Lock()
			s.healthy = false
			s.mu.Unlock()
			incEventMetric("error")

			if errors.Is(err, base.ErrAuthenticationFailed) {
				s.log.Error("Failed to authenticate to Cerbos Hub", zap.Error(err))
				s.removeBundle(false)
				return backoff.Permanent(err)
			}
		}
		return err
	}

	notify := func(err error, next time.Duration) {
		s.log.Warn(fmt.Sprintf("Retrying failed watch call in %s", next), zap.Error(err))
	}

	s.log.Debug("Calling watch RPC")
	if err := backoff.RetryNotify(op, backoffCtx, notify); err != nil {
		return 0, err
	}

	metrics.Add(ctx, metrics.HubConnected(), 1)

	eventChan := watchHandle.ServerEvents()
	errorChan := watchHandle.Errors()
	doneChan := ctx.Done()

	// Returning a nil error causes the connection to be re-established.
	// Returning a non-nil error terminates the process.
	for {
		select {
		case evt, ok := <-eventChan:
			if !ok {
				s.log.Debug("Server event channel terminated")
				return 0, nil
			}

			switch evt.Kind {
			case cloudapi.ServerEventError:
				incEventMetric("error")
				if errors.Is(evt.Error, cloudapi.ErrBundleNotFound) {
					s.log.Error("Bundle label does not exist", zap.Error(evt.Error))
					s.removeBundle(true)
					if err := watchHandle.ActiveBundleChanged(cloudapi.BundleIDOrphaned); err != nil {
						s.log.Warn("Failed to notify server about orphaned bundle", zap.Error(err))
					}

					return 0, cloudapi.ErrBundleNotFound
				}

				s.log.Warn("Restarting watch", zap.Error(evt.Error))
				return 0, nil
			case cloudapi.ServerEventReconnect:
				incEventMetric("reconnect")
				s.log.Debug(fmt.Sprintf("Server requests reconnect in %s", evt.ReconnectBackoff))
				return evt.ReconnectBackoff, nil
			case cloudapi.ServerEventBundleRemoved:
				incEventMetric("bundle_removed")
				s.log.Warn("Bundle label no longer exists")
				s.removeBundle(true)
				if err := watchHandle.ActiveBundleChanged(cloudapi.BundleIDOrphaned); err != nil {
					s.log.Warn("Failed to notify server about bundle swap", zap.Error(err))
				}
			case cloudapi.ServerEventNewBundle:
				incEventMetric("bundle_update")
				if err := s.swapBundle(evt.NewBundlePath); err != nil {
					s.log.Warn("Failed to swap bundle", zap.Error(err))
				} else {
					if err := watchHandle.ActiveBundleChanged(s.activeBundleVersion()); err != nil {
						s.log.Warn("Failed to notify server about bundle swap", zap.Error(err))
					}
				}

			default:
				incEventMetric("unknown")
				s.log.Debug("Unknown server event kind", zap.Uint8("event", uint8(evt.Kind)))
			}
		case err := <-errorChan:
			s.log.Warn("Restarting watch", zap.Error(err))
			return 0, nil
		case <-doneChan:
			return 0, ctx.Err()
		}
	}
}

func (s *RemoteSource) Driver() string {
	return DriverName
}

func (s *RemoteSource) IsHealthy() bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.healthy
}

func (s *RemoteSource) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return s.bundle.GetFirstMatch(ctx, candidates)
}

func (s *RemoteSource) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return s.bundle.InspectPolicies(ctx, params)
}

func (s *RemoteSource) ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return s.bundle.ListPolicyIDs(ctx, params)
}

func (s *RemoteSource) ListSchemaIDs(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return s.bundle.ListSchemaIDs(ctx)
}

func (s *RemoteSource) LoadSchema(ctx context.Context, id string) (io.ReadCloser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return s.bundle.LoadSchema(ctx, id)
}

func (s *RemoteSource) Reload(ctx context.Context) error {
	return s.fetchBundle(ctx)
}

func (s *RemoteSource) SourceKind() string {
	return "remote"
}

func (s *RemoteSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bundle != nil {
		err := s.bundle.Close()
		s.bundle = nil
		return err
	}

	return nil
}
