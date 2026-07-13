// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/spf13/afero"
	"go.uber.org/zap"

	"github.com/cerbos/cloud-api/base"
	bundleapi "github.com/cerbos/cloud-api/bundle"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"
	hubapi "github.com/cerbos/cloud-api/hub"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	defaultReconnectBackoff = 5 * time.Second
	noBundleInitialInterval = 60 * time.Second
	noBundleMaxInterval     = 10 * time.Minute
	noBundleMaxCount        = 10
)

var (
	_ storage.BinaryStore  = (*RemoteSource)(nil)
	_ storage.Reloadable   = (*RemoteSource)(nil)
	_ storage.Instrumented = (*RemoteSource)(nil)
)

type Bundle interface {
	io.Closer
	ID() string
	Release() error
	Type() bundlev2.BundleType
	InspectPolicies(context.Context, storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error)
	ListPolicyIDs(context.Context, storage.ListPolicyIDsParams) ([]string, error)
	ListSchemaIDs(context.Context) ([]string, error)
	LoadSchema(context.Context, string) (io.ReadCloser, error)
	GetFirstMatch(context.Context, []namer.ModuleID) (*runtimev1.RunnablePolicySet, error)
	GetAll(context.Context) ([]*runtimev1.RunnablePolicySet, error)
	GetAllMatching(context.Context, []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error)
	RepoStats(context.Context) storage.RepoStats
}

type cloudAPIClient interface {
	BootstrapBundle(context.Context) (string, bundlev2.BundleType, []byte, error)
	GetBundle(context.Context) (string, bundlev2.BundleType, []byte, error)
	GetCachedBundle() (string, error)
	WatchBundle(context.Context) (bundleapi.WatchHandle, error)
}

type cloudAPIv2 struct {
	client Client
	source bundleapi.Source
}

func (apiv2 *cloudAPIv2) BootstrapBundle(ctx context.Context) (string, bundlev2.BundleType, []byte, error) {
	return apiv2.client.BootstrapBundle(ctx, apiv2.source)
}

func (apiv2 *cloudAPIv2) GetBundle(ctx context.Context) (string, bundlev2.BundleType, []byte, error) {
	return apiv2.client.GetBundle(ctx, apiv2.source)
}

func (apiv2 *cloudAPIv2) GetCachedBundle() (string, error) {
	return apiv2.client.GetCachedBundle(apiv2.source)
}

func (apiv2 *cloudAPIv2) WatchBundle(ctx context.Context) (bundleapi.WatchHandle, error) {
	return apiv2.client.WatchBundle(ctx, apiv2.source)
}

// RemoteSource implements a bundle store that loads bundles from a remote source.
type RemoteSource struct {
	hub       ClientProvider
	scratchFS afero.Fs
	client    cloudAPIClient
	log       *zap.Logger
	conf      *Conf
	bundle    Bundle
	subs      *storage.SubscriptionManager
	mu        sync.RWMutex
	healthy   bool
}

func (s *RemoteSource) Subscribe(sub storage.Subscriber) {
	s.subs.Subscribe(sub)
}

func (s *RemoteSource) Unsubscribe(sub storage.Subscriber) {
	s.subs.Unsubscribe(sub)
}

func NewRemoteSource(conf *Conf) (*RemoteSource, error) {
	hubInstance, err := hub.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to establish Cerbos Hub connection: %w", err)
	}

	return NewRemoteSourceWithHub(conf, hubClientProvider{Hub: hubInstance})
}

type ClientProvider interface {
	Client(bundleapi.ClientConf) (Client, error)
}

type hubClientProvider struct {
	*hubapi.Hub
}

func (h hubClientProvider) Client(conf bundleapi.ClientConf) (Client, error) {
	return h.BundleClient(conf)
}

type Client interface {
	BootstrapBundle(context.Context, bundleapi.Source) (string, bundlev2.BundleType, []byte, error)
	GetBundle(context.Context, bundleapi.Source) (string, bundlev2.BundleType, []byte, error)
	GetCachedBundle(bundleapi.Source) (string, error)
	WatchBundle(context.Context, bundleapi.Source) (bundleapi.WatchHandle, error)
}

func NewRemoteSourceWithHub(conf *Conf, hub ClientProvider) (*RemoteSource, error) {
	return &RemoteSource{
		conf:      conf,
		hub:       hub,
		healthy:   false,
		log:       zap.L().Named(DriverName),
		scratchFS: afero.NewBasePathFs(afero.NewOsFs(), conf.Remote.TempDir),
	}, nil
}

func (s *RemoteSource) Init(ctx context.Context) error {
	s.subs = storage.NewSubscriptionManager(ctx)

	clientConf := bundleapi.ClientConf{
		CacheDir: s.conf.Remote.CacheDir,
		TempDir:  s.conf.Remote.TempDir,
	}

	client, err := s.hub.Client(clientConf)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	var source bundleapi.Source
	switch {
	case s.conf.Remote.DeploymentID != "":
		source = bundleapi.DeploymentID(s.conf.Remote.DeploymentID)
	case s.conf.Remote.PlaygroundID != "":
		source = bundleapi.PlaygroundID(s.conf.Remote.PlaygroundID)
	default:
		return errors.New("no bundle source configured")
	}

	s.client = &cloudAPIv2{client: client, source: source}
	s.log = s.log.With(zap.Stringer("source", source))

	// fail fast if the service is down
	if err := s.fetchBundle(ctx); err != nil {
		return err
	}

	if !s.conf.Remote.DisableAutoUpdate {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = noBundleInitialInterval
		b.MaxInterval = noBundleMaxInterval
		b.Multiplier = 2

		go s.startWatchLoop(ctx, &noBundleBackoff{backoff: b})
	}

	return nil
}

type noBundleBackoff struct {
	backoff backoff.BackOff
	count   uint
}

func (b *noBundleBackoff) NextBackOff() time.Duration {
	b.count++
	if b.count >= noBundleMaxCount {
		return backoff.Stop
	}
	return b.backoff.NextBackOff()
}

func (b *noBundleBackoff) Reset() {
	b.backoff.Reset()
	b.count = 0
}

func (s *RemoteSource) fetchBundle(ctx context.Context) error {
	var bdlPath string
	var bdlType bundlev2.BundleType
	var encryptionKey []byte
	var err error

	if !s.conf.Remote.DisableBootstrap {
		s.log.Info("Fetching bootstrap bundle")
		bdlPath, bdlType, encryptionKey, err = s.client.BootstrapBundle(ctx)
		if err == nil {
			s.log.Debug("Using bootstrap bundle")
			return s.swapBundle(bdlPath, encryptionKey, bdlType)
		}

		if errors.Is(err, bundleapi.ErrBootstrappingNotSupported) {
			s.log.Info("Skipped fetching bootstrap bundle", zap.Error(err))
		} else {
			s.log.Warn("Failed to fetch bootstrap bundle", zap.Error(err))
		}
	}

	s.log.Info("Fetching bundle from the API")
	bdlPath, bdlType, encryptionKey, err = s.client.GetBundle(ctx)
	if err != nil {
		s.log.Error("Failed to fetch bundle using the API", zap.Error(err))
		metrics.Inc(ctx, metrics.BundleFetchErrorsCount())
		return fmt.Errorf("failed to fetch bundle: %w", err)
	}

	s.log.Debug("Using bundle fetched from the API")
	return s.swapBundle(bdlPath, encryptionKey, bdlType)
}

func (s *RemoteSource) removeBundle(healthy bool) {
	var oldBundle Bundle
	s.mu.Lock()
	oldBundle = s.bundle
	s.bundle = nil
	s.healthy = healthy
	s.mu.Unlock()

	if err := oldBundle.Release(); err != nil {
		s.log.Warn("Failed to release old bundle", zap.Error(err))
	}
}

func (s *RemoteSource) swapBundle(bundlePath string, encryptionKey []byte, bundleType bundlev2.BundleType) error {
	s.log.Debug("Swapping bundle", zap.String("path", bundlePath), zap.String("bundle-type", bundleType.String()))
	opts := OpenOpts{
		Source:        "remote",
		BundlePath:    bundlePath,
		EncryptionKey: encryptionKey,
		ScratchFS:     s.scratchFS,
		CacheSize:     s.conf.CacheSize,
	}

	var newBundle Bundle
	var err error
	if bundleType == bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE {
		newBundle, err = OpenRuleTableBundle(opts)
		if err != nil {
			s.log.Error("Failed to open rule table bundle", zap.Error(err))
			return fmt.Errorf("failed to open rule table bundle: %w", err)
		}
	} else {
		newBundle, err = OpenLegacyBundle(opts)
		if err != nil {
			s.log.Error("Failed to open legacy bundle", zap.Error(err))
			return fmt.Errorf("failed to open legacy bundle: %w", err)
		}
	}

	var oldBundle Bundle
	s.mu.Lock()
	oldBundle = s.bundle
	s.bundle = newBundle
	s.healthy = true
	s.mu.Unlock()

	s.subs.NotifySubscribers(storage.NewReloadEvent())

	if oldBundle != nil {
		if err := oldBundle.Release(); err != nil {
			s.log.Warn("Failed to release old bundle", zap.Error(err))
		}
	}

	metrics.Inc(context.Background(), metrics.BundleStoreUpdatesCount())
	metrics.Record(context.Background(), metrics.StoreLastSuccessfulRefresh(), time.Now().UnixMilli(), metrics.DriverKey(DriverName))

	return nil
}

func (s *RemoteSource) activeBundleID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.bundle.ID()
}

func (s *RemoteSource) startWatchLoop(ctx context.Context, noBundleBackoff backoff.BackOff) {
	s.log.Info("Starting watch")
	wait, err := s.startWatch(ctx)
	if err != nil {
		if !errors.Is(err, bundleapi.ErrBundleNotFound) {
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
	op := func() (bundleapi.WatchHandle, error) {
		watchHandle, err := s.client.WatchBundle(ctx)
		if err != nil {
			s.mu.Lock()
			s.healthy = false
			s.mu.Unlock()
			incEventMetric("error")

			switch {
			case errors.Is(err, base.ErrAuthenticationFailed):
				s.log.Error("Failed to authenticate to Cerbos Hub", zap.Error(err))
				s.removeBundle(false)
				return nil, backoff.Permanent(err)
			case errors.Is(err, bundleapi.ErrPermissionDenied):
				s.log.Error("Permission denied: make sure the credentials used are the correct ones for the Cerbos Hub Deployment this PDP is configured to use", zap.Error(err))
				s.removeBundle(false)
				return nil, backoff.Permanent(err)
			}
		}
		return watchHandle, err
	}

	notify := func(err error, next time.Duration) {
		s.log.Warn(fmt.Sprintf("Retrying failed watch call in %s", next), zap.Error(err))
	}

	s.log.Debug("Calling watch RPC")
	watchHandle, err := backoff.Retry(
		ctx, op,
		backoff.WithMaxElapsedTime(0), // retry indefinitely
		backoff.WithNotify(notify),
	)
	if err != nil {
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
			case bundleapi.ServerEventError:
				incEventMetric("error")
				switch {
				case errors.Is(evt.Error, bundleapi.ErrBundleNotFound):
					s.log.Error("Bundle does not exist", zap.Error(evt.Error))
					s.removeBundle(true)
					if err := watchHandle.ActiveBundleChanged(bundleapi.BundleIDOrphaned); err != nil {
						s.log.Warn("Failed to notify server about orphaned bundle", zap.Error(err))
					}

					return 0, bundleapi.ErrBundleNotFound

				case errors.Is(evt.Error, bundleapi.ErrPermissionDenied):
					s.log.Error("Permission denied", zap.Error(evt.Error))
					s.removeBundle(true)
					if err := watchHandle.ActiveBundleChanged(bundleapi.BundleIDOrphaned); err != nil {
						s.log.Warn("Failed to notify server about orphaned bundle", zap.Error(err))
					}

					return 0, bundleapi.ErrPermissionDenied
				}

				s.log.Warn("Restarting watch", zap.Error(evt.Error))
				return 0, nil
			case bundleapi.ServerEventReconnect:
				incEventMetric("reconnect")
				s.log.Debug(fmt.Sprintf("Server requests reconnect in %s", evt.ReconnectBackoff))
				return evt.ReconnectBackoff, nil
			case bundleapi.ServerEventBundleRemoved:
				incEventMetric("bundle_removed")
				s.log.Warn("Bundle label no longer exists")
				s.removeBundle(true)
				if err := watchHandle.ActiveBundleChanged(bundleapi.BundleIDOrphaned); err != nil {
					s.log.Warn("Failed to notify server about bundle swap", zap.Error(err))
				}
			case bundleapi.ServerEventNewBundle:
				incEventMetric("bundle_update")
				if err := s.swapBundle(evt.NewBundlePath, evt.EncryptionKey, evt.BundleType); err != nil {
					s.log.Warn("Failed to swap bundle", zap.Error(err))
				} else {
					if err := watchHandle.ActiveBundleChanged(s.activeBundleID()); err != nil {
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

func (s *RemoteSource) GetRuleTable() (*ruletable.RuleTable, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if rtBundle, ok := s.bundle.(*RuleTableBundle); ok {
		return rtBundle.GetRuleTable()
	}

	return nil, storage.ErrUnsupportedOperation
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

func (s *RemoteSource) GetAll(ctx context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return s.bundle.GetAll(ctx)
}

func (s *RemoteSource) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return s.bundle.GetAllMatching(ctx, modIDs)
}

func (s *RemoteSource) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
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

func (s *RemoteSource) RepoStats(ctx context.Context) storage.RepoStats {
	return s.bundle.RepoStats(ctx)
}

func (s *RemoteSource) Source() *auditv1.PolicySource {
	hubPolicySource := &auditv1.PolicySource_Hub{}
	switch {
	case s.conf.Remote.DeploymentID != "":
		hubPolicySource.Source = &auditv1.PolicySource_Hub_RemoteBundle_{
			RemoteBundle: &auditv1.PolicySource_Hub_RemoteBundle{
				DeploymentId: s.conf.Remote.DeploymentID,
				BundleId:     s.activeBundleID(),
			},
		}
	case s.conf.Remote.PlaygroundID != "":
		hubPolicySource.Source = &auditv1.PolicySource_Hub_PlaygroundId{
			PlaygroundId: s.conf.Remote.PlaygroundID,
		}
	}

	return &auditv1.PolicySource{
		Source: &auditv1.PolicySource_Hub_{
			Hub: hubPolicySource,
		},
	}
}

func (s *RemoteSource) SourceKind() string {
	return "remote"
}

func (s *RemoteSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bundle == nil {
		return nil
	}

	err := s.bundle.Close()
	s.bundle = nil
	return err
}
