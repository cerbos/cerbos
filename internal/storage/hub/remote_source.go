// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/spf13/afero"
	"go.uber.org/zap"

	"github.com/cerbos/cloud-api/base"
	bundleapi "github.com/cerbos/cloud-api/bundle"
	bundleapiv2 "github.com/cerbos/cloud-api/bundle/v2"
	"github.com/cerbos/cloud-api/credentials"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"
	hubapi "github.com/cerbos/cloud-api/hub"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/storage"
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

	playgroundLabelPattern = regexp.MustCompile(`^playground/[A-Z0-9]{12}$`)

	ErrOfflineModeNotAvailable = errors.New("offline mode is not available when bundle version is set to 2")
)

type cloudAPIClient interface {
	BootstrapBundle(context.Context) (string, bundlev2.BundleType, []byte, error)
	GetBundle(context.Context) (string, bundlev2.BundleType, []byte, error)
	GetCachedBundle() (string, error)
	OpenCredentials() *credentials.Credentials
	WatchBundle(context.Context) (bundleapi.WatchHandle, error)
}

type cloudAPIv1 struct {
	client      ClientV1
	bundleLabel string
	playground  bool
}

func (apiv1 *cloudAPIv1) BootstrapBundle(ctx context.Context) (string, bundlev2.BundleType, []byte, error) {
	if apiv1.playground {
		return "", bundlev2.BundleType_BUNDLE_TYPE_UNSPECIFIED, nil, bundleapi.ErrBootstrappingNotSupported
	}

	path, err := apiv1.client.BootstrapBundle(ctx, apiv1.bundleLabel)
	return path, bundlev2.BundleType_BUNDLE_TYPE_LEGACY, nil, err
}

func (apiv1 *cloudAPIv1) GetBundle(ctx context.Context) (string, bundlev2.BundleType, []byte, error) {
	path, err := apiv1.client.GetBundle(ctx, apiv1.bundleLabel)
	return path, bundlev2.BundleType_BUNDLE_TYPE_LEGACY, nil, err
}

func (apiv1 *cloudAPIv1) GetCachedBundle() (string, error) {
	return apiv1.client.GetCachedBundle(apiv1.bundleLabel)
}

func (apiv1 *cloudAPIv1) OpenCredentials() *credentials.Credentials {
	if apiv1.playground {
		return nil
	}
	return apiv1.client.HubCredentials()
}

func (apiv1 *cloudAPIv1) WatchBundle(ctx context.Context) (bundleapi.WatchHandle, error) {
	return apiv1.client.WatchBundle(ctx, apiv1.bundleLabel)
}

type cloudAPIv2 struct {
	client ClientV2
	source bundleapiv2.Source
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

func (apiv2 *cloudAPIv2) OpenCredentials() *credentials.Credentials {
	return nil
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
	bundle    *Bundle
	source    *auditv1.PolicySource
	*storage.SubscriptionManager
	bundleVersion bundleapi.Version
	mu            sync.RWMutex
	healthy       bool
}

func NewRemoteSource(conf *Conf) (*RemoteSource, error) {
	hubInstance, err := hub.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to establish Cerbos Hub connection: %w", err)
	}

	return NewRemoteSourceWithHub(conf, hubClientProvider{Hub: hubInstance})
}

type ClientProvider interface {
	V1(bundleapi.ClientConf) (ClientV1, error)
	V2(bundleapi.ClientConf) (ClientV2, error)
}

type hubClientProvider struct {
	*hubapi.Hub
}

func (h hubClientProvider) V1(conf bundleapi.ClientConf) (ClientV1, error) {
	return h.BundleClient(conf)
}

func (h hubClientProvider) V2(conf bundleapi.ClientConf) (ClientV2, error) {
	return h.BundleClientV2(conf)
}

type ClientV1 interface {
	HubCredentials() *credentials.Credentials
	BootstrapBundle(context.Context, string) (string, error)
	GetBundle(context.Context, string) (string, error)
	GetCachedBundle(string) (string, error)
	WatchBundle(context.Context, string) (bundleapi.WatchHandle, error)
}

type ClientV2 interface {
	BootstrapBundle(context.Context, bundleapiv2.Source) (string, bundlev2.BundleType, []byte, error)
	GetBundle(context.Context, bundleapiv2.Source) (string, bundlev2.BundleType, []byte, error)
	GetCachedBundle(bundleapiv2.Source) (string, error)
	WatchBundle(context.Context, bundleapiv2.Source) (bundleapi.WatchHandle, error)
}

func NewRemoteSourceWithHub(conf *Conf, hub ClientProvider) (*RemoteSource, error) {
	var bundleVersion bundleapi.Version
	switch {
	case strings.TrimSpace(conf.Remote.BundleLabel) != "":
		bundleVersion = bundleapi.Version1

	case strings.TrimSpace(conf.Remote.DeploymentID) != "":
		bundleVersion = bundleapi.Version2

	case strings.TrimSpace(conf.Remote.PlaygroundID) != "":
		bundleVersion = bundleapi.Version2

	default:
		return nil, errors.New("bundleLabel, deploymentID or playgroundID must be specified")
	}

	return &RemoteSource{
		bundleVersion: bundleVersion,
		conf:          conf,
		hub:           hub,
		healthy:       false,
		log:           zap.L().Named(DriverName),
		scratchFS:     afero.NewBasePathFs(afero.NewOsFs(), conf.Remote.TempDir),
	}, nil
}

func (s *RemoteSource) Init(ctx context.Context) error {
	s.SubscriptionManager = storage.NewSubscriptionManager(ctx)
	bundleType := bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE
	clientConf := bundleapi.ClientConf{
		CacheDir:   s.conf.Remote.CacheDir,
		TempDir:    s.conf.Remote.TempDir,
		BundleType: &bundleType,
	}

	hub := &auditv1.PolicySource_Hub{}
	s.source = &auditv1.PolicySource{Source: &auditv1.PolicySource_Hub_{Hub: hub}}

	switch s.bundleVersion {
	case bundleapi.Version1:
		clientv1, err := s.hub.V1(clientConf)
		if err != nil {
			return fmt.Errorf("failed to create API client v1: %w", err)
		}

		hub.Source = &auditv1.PolicySource_Hub_Label{Label: s.conf.Remote.BundleLabel}

		s.client = &cloudAPIv1{
			client:      clientv1,
			bundleLabel: s.conf.Remote.BundleLabel,
			playground:  playgroundLabelPattern.MatchString(s.conf.Remote.BundleLabel),
		}
		s.log = s.log.With(zap.String("label", s.conf.Remote.BundleLabel))

	case bundleapi.Version2:
		clientv2, err := s.hub.V2(clientConf)
		if err != nil {
			return fmt.Errorf("failed to create API client v2: %w", err)
		}

		var source bundleapiv2.Source
		switch {
		case s.conf.Remote.DeploymentID != "":
			hub.Source = &auditv1.PolicySource_Hub_DeploymentId{DeploymentId: s.conf.Remote.DeploymentID}
			source = bundleapiv2.DeploymentID(s.conf.Remote.DeploymentID)
		case s.conf.Remote.PlaygroundID != "":
			hub.Source = &auditv1.PolicySource_Hub_PlaygroundId{PlaygroundId: s.conf.Remote.PlaygroundID}
			source = bundleapiv2.PlaygroundID(s.conf.Remote.PlaygroundID)
		default:
			return errors.New("no bundle source configured")
		}

		s.client = &cloudAPIv2{client: clientv2, source: source}
		s.log = s.log.With(zap.Stringer("source", source))

	default:
		return fmt.Errorf("unsupported bundle version: %d", s.bundleVersion)
	}

	// Ideally we want to be able to automatically switch between online and offline modes.
	// That logic is complicated to implement and test in the little time we have. There are open questions
	// about expected behaviour as well. For example, is it preferable to use a stale copy from cache or fail fast?
	// So, this initial version just provides an escape hatch to manually deal with downtime by putting the PDP
	// into offline mode.
	// TODO(cell): Implement automatic online/offline mode
	// TODO(oguzhan): Get rid of offline mode when we no longer support bundle.Version1.
	if shouldWorkOffline() {
		if s.bundleVersion == bundleapi.Version2 {
			return ErrOfflineModeNotAvailable
		}

		s.log.Warn("Working in offline mode because the CERBOS_HUB_OFFLINE environment variable is set")
		return s.fetchBundleOffline()
	}

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

func shouldWorkOffline() bool {
	v := hub.GetEnv(hub.OfflineKey)
	offline, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}

	return offline
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

func (s *RemoteSource) fetchBundleOffline() error {
	// TODO(oguzhan): Get rid of offline mode when we no longer support bundle.Version1.
	s.log.Info("Looking for cached bundle")
	bdlPath, err := s.client.GetCachedBundle()
	if err != nil {
		s.log.Error("Failed to find cached bundle", zap.Error(err))
		return fmt.Errorf("failed to find cached bundle: %w", err)
	}

	return s.swapBundle(bdlPath, nil, bundlev2.BundleType_BUNDLE_TYPE_LEGACY)
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

func (s *RemoteSource) swapBundle(bundlePath string, encryptionKey []byte, bundleType bundlev2.BundleType) error {
	s.log.Debug("Swapping bundle", zap.String("path", bundlePath), zap.String("bundle-type", bundleType.String()))
	opts := OpenOpts{
		Source:        "remote",
		BundlePath:    bundlePath,
		Credentials:   s.client.OpenCredentials(),
		EncryptionKey: encryptionKey,
		ScratchFS:     s.scratchFS,
		CacheSize:     s.conf.CacheSize,
	}

	var bundle *Bundle
	var err error
	switch s.bundleVersion {
	case bundleapi.Version1:
		if bundle, err = Open(opts); err != nil {
			s.log.Error("Failed to open bundle", zap.Error(err))
			return fmt.Errorf("failed to open bundle: %w", err)
		}
	case bundleapi.Version2:
		if bundle, err = OpenV2(opts); err != nil {
			s.log.Error("Failed to open bundle v2", zap.Error(err))
			return fmt.Errorf("failed to open bundle v2: %w", err)
		}
	default:
		return fmt.Errorf("unsupported bundle version: %d", s.bundleVersion)
	}

	s.mu.Lock()
	oldBundle := s.bundle
	s.bundle = bundle
	s.healthy = true
	s.mu.Unlock()

	s.NotifySubscribers(storage.NewReloadEvent())

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

	if s.bundle == nil || s.bundle.manifest == nil || s.bundle.manifest.Meta == nil {
		return bundleapi.BundleIDUnknown
	}

	return s.bundle.manifest.Meta.BundleId
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

			if errors.Is(err, base.ErrAuthenticationFailed) {
				s.log.Error("Failed to authenticate to Cerbos Hub", zap.Error(err))
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
	watchHandle, err := backoff.Retry(ctx, op,
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
				if errors.Is(evt.Error, bundleapi.ErrBundleNotFound) {
					s.log.Error("Bundle label does not exist", zap.Error(evt.Error))
					s.removeBundle(true)
					if err := watchHandle.ActiveBundleChanged(bundleapi.BundleIDOrphaned); err != nil {
						s.log.Warn("Failed to notify server about orphaned bundle", zap.Error(err))
					}

					return 0, bundleapi.ErrBundleNotFound
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

func (s *RemoteSource) Source() *auditv1.PolicySource {
	return s.source
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
