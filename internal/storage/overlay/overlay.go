// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"errors"
	"fmt"
	"io"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

const DriverName = "overlay"

var errMethodNotImplemented = errors.New("method not supported for store type")

var _ Store = (*WrappedSourceStore)(nil)

// The interface is defined here because placing in storage causes a circular dependency,
// possibly because the store-wrapping-stores pattern somewhat breaks our boundaries.
// TODO(saml) consider a dedicated package (separate from `store`) to cater for this?
type Store interface {
	storage.SourceStore
	// TODO(saml) implement methods for all of these, with appropriate type assertions
	storage.MutableStore
	storage.Reloadable
	storage.Instrumented
	// GetOverlayPolicyLoader returns a PolicyLoader implementation that wraps two SourceStores
	GetOverlayPolicyLoader(ctx context.Context, schemaMgr schema.Manager) (engine.PolicyLoader, error)
}

func init() {
	// TODO(saml), need to somehow register both `baseDriver` and `overlayDriver` keys in the `drivers` cache
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read overlay configuration: %w", err)
		}

		return NewStore(ctx, conf, confW)
	})
}

func NewStore(ctx context.Context, conf *Conf, confW *config.Wrapper) (*WrappedSourceStore, error) {
	getStore := func(key string) (storage.SourceStore, error) {
		cons, err := storage.GetDriverConstructor(key)
		if err != nil {
			return nil, fmt.Errorf("unknown storage driver [%s]", key)
		}

		store, err := cons(ctx, confW)
		if err != nil {
			return nil, fmt.Errorf("failed to create store: %w", err)
		}

		sourceStore, ok := store.(storage.SourceStore)
		if !ok {
			return nil, fmt.Errorf("store is incorrect type for key [%s]: %w", key, err)
		}

		return sourceStore, nil
	}

	baseStore, err := getStore(conf.BaseDriver)
	if err != nil {
		return nil, fmt.Errorf("failed to create base policy loader: %w", err)
	}

	fallbackStore, err := getStore(conf.FallbackDriver)
	if err != nil {
		return nil, fmt.Errorf("failed to create fallback policy loader: %w", err)
	}

	return &WrappedSourceStore{
		conf:                conf,
		baseStore:           baseStore,
		fallbackStore:       fallbackStore,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}, nil
}

type WrappedSourceStore struct {
	conf                 *Conf
	baseStore            storage.SourceStore
	fallbackStore        storage.SourceStore
	basePolicyLoader     engine.PolicyLoader
	fallbackPolicyLoader engine.PolicyLoader
	*storage.SubscriptionManager
	nFailures int
}

// GetOverlayPolicyLoader ... TODO(saml).
func (s *WrappedSourceStore) GetOverlayPolicyLoader(ctx context.Context, schemaMgr schema.Manager) (engine.PolicyLoader, error) {
	// TODO(saml) lazy or greedy store/compile mgr creation??
	baseCompileMgr, err := compile.NewManager(ctx, s.baseStore, schemaMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create base compile manager: %w", err)
	}
	s.basePolicyLoader = baseCompileMgr

	fallbackCompileMgr, err := compile.NewManager(ctx, s.fallbackStore, schemaMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create fallback compile manager: %w", err)
	}
	s.fallbackPolicyLoader = fallbackCompileMgr

	return s.getActivePolicyLoader(), nil
}

func (s *WrappedSourceStore) getActivePolicyLoader() engine.PolicyLoader {
	if s.nFailures > s.conf.FailoverThreshold {
		return s.fallbackPolicyLoader
	}
	return s.basePolicyLoader
}

func (s *WrappedSourceStore) getActiveStore() storage.SourceStore {
	if s.nFailures > s.conf.FailoverThreshold {
		return s.fallbackStore
	}
	return s.baseStore
}

func (s *WrappedSourceStore) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	// TODO(saml) failover
	return s.getActivePolicyLoader().GetPolicySet(ctx, id)
}

func (s *WrappedSourceStore) Driver() string {
	return DriverName
}

func (s *WrappedSourceStore) ListPolicyIDs(ctx context.Context, includeDisabled bool) ([]string, error) {
	return s.getActiveStore().ListPolicyIDs(ctx, includeDisabled)
}

func (s *WrappedSourceStore) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return s.getActiveStore().ListSchemaIDs(ctx)
}

func (s *WrappedSourceStore) LoadSchema(ctx context.Context, url string) (io.ReadCloser, error) {
	return s.getActiveStore().LoadSchema(ctx, url)
}

func (s *WrappedSourceStore) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return s.getActiveStore().GetCompilationUnits(ctx, ids...)
}

func (s *WrappedSourceStore) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return s.getActiveStore().GetDependents(ctx, ids...)
}

func (s *WrappedSourceStore) LoadPolicy(ctx context.Context, file ...string) ([]*policy.Wrapper, error) {
	return s.getActiveStore().LoadPolicy(ctx, file...)
}

func (s *WrappedSourceStore) AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error {
	if ms, ok := s.getActiveStore().(storage.MutableStore); ok {
		return ms.AddOrUpdate(ctx, policies...)
	}
	return errMethodNotImplemented
}

func (s *WrappedSourceStore) AddOrUpdateSchema(ctx context.Context, schemas ...*schemav1.Schema) error {
	if ms, ok := s.getActiveStore().(storage.MutableStore); ok {
		return ms.AddOrUpdateSchema(ctx, schemas...)
	}
	return errMethodNotImplemented
}

func (s *WrappedSourceStore) Disable(ctx context.Context, policyKey ...string) (uint32, error) {
	if ms, ok := s.getActiveStore().(storage.MutableStore); ok {
		return ms.Disable(ctx, policyKey...)
	}
	return 0, errMethodNotImplemented
}

func (s *WrappedSourceStore) Enable(ctx context.Context, policyKey ...string) (uint32, error) {
	if ms, ok := s.getActiveStore().(storage.MutableStore); ok {
		return ms.Enable(ctx, policyKey...)
	}
	return 0, errMethodNotImplemented
}

func (s *WrappedSourceStore) DeleteSchema(ctx context.Context, ids ...string) (uint32, error) {
	if ms, ok := s.getActiveStore().(storage.MutableStore); ok {
		return ms.DeleteSchema(ctx, ids...)
	}
	return 0, errMethodNotImplemented
}

func (s *WrappedSourceStore) Delete(ctx context.Context, ids ...namer.ModuleID) error {
	if ms, ok := s.getActiveStore().(storage.MutableStore); ok {
		return ms.Delete(ctx, ids...)
	}
	return errMethodNotImplemented
}

func (s *WrappedSourceStore) Reload(ctx context.Context) error {
	if ms, ok := s.getActiveStore().(storage.Reloadable); ok {
		return ms.Reload(ctx)
	}
	return errMethodNotImplemented
}

func (s *WrappedSourceStore) RepoStats(ctx context.Context) storage.RepoStats {
	// TODO(saml) gather stats for both stores?
	if ms, ok := s.getActiveStore().(storage.Instrumented); ok {
		return ms.RepoStats(ctx)
	}
	// TODO(saml) pointless return of empty stats?
	return storage.RepoStats{}
}
