// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"fmt"
	"io"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/sony/gobreaker"
)

const (
	DriverName = "overlay"
)

var _ Overlay = (*Store)(nil)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read overlay configuration: %w", err)
		}

		return NewStore(ctx, conf, confW)
	})
}

func NewStore(ctx context.Context, conf *Conf, confW *config.Wrapper) (*Store, error) {
	getStore := func(key string) (storage.SourceStore, error) {
		cons, err := storage.GetDriverConstructor(key)
		if err != nil {
			return nil, fmt.Errorf("unknown storage driver [%s]", key)
		}

		store, err := cons(ctx, confW)
		if err != nil {
			return nil, fmt.Errorf("failed to create overlay store: %w", err)
		}

		sourceStore, ok := store.(storage.SourceStore)
		if !ok {
			return nil, fmt.Errorf("store is incorrect type for key [%s]: %w", key, err)
		}

		return sourceStore, nil
	}

	logger := zap.S().Named(confKey+".store").With("baseDriver", conf.BaseDriver, "fallbackDriver", conf.FallbackDriver)

	baseStore, err := getStore(conf.BaseDriver)
	if err != nil {
		logger.Errorw("Failed to initialize overlay base store", "error", err)
		return nil, fmt.Errorf("failed to create base policy loader: %w", err)
	}

	fallbackStore, err := getStore(conf.FallbackDriver)
	if err != nil {
		logger.Errorw("Failed to initialize overlay fallback store", "error", err)
		return nil, fmt.Errorf("failed to create fallback policy loader: %w", err)
	}

	return &Store{
		log:                 logger,
		conf:                conf,
		baseStore:           baseStore,
		fallbackStore:       fallbackStore,
		circuitBreaker:      newCircuitBreaker(conf),
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}, nil
}

type Store struct {
	log                  *zap.SugaredLogger
	conf                 *Conf
	baseStore            storage.SourceStore
	fallbackStore        storage.SourceStore
	basePolicyLoader     engine.PolicyLoader
	fallbackPolicyLoader engine.PolicyLoader
	circuitBreaker       *gobreaker.CircuitBreaker
	*storage.SubscriptionManager
}

func newCircuitBreaker(conf *Conf) *gobreaker.CircuitBreaker {
	breakerSettings := gobreaker.Settings{
		Name: "Store",
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= uint32(conf.FallbackErrorThreshold)
		},
		Interval: conf.FallbackErrorWindow,
		Timeout:  0,
	}
	return gobreaker.NewCircuitBreaker(breakerSettings)
}

// GetOverlayPolicyLoader instantiates both the base and fallback policy loaders and then returns itself.
func (s *Store) GetOverlayPolicyLoader(ctx context.Context, schemaMgr schema.Manager) (engine.PolicyLoader, error) {
	var err error
	s.basePolicyLoader, err = compile.NewManager(ctx, s.baseStore, schemaMgr)
	if err != nil {
		s.log.Errorw("Failed to create base compile manager", "error", err)
		return nil, fmt.Errorf("failed to create base compile manager: %w", err)
	}

	s.fallbackPolicyLoader, err = compile.NewManager(ctx, s.fallbackStore, schemaMgr)
	if err != nil {
		s.log.Errorw("Failed to create fallback compile manager", "error", err)
		return nil, fmt.Errorf("failed to create fallback compile manager: %w", err)
	}

	return s, nil
}

func (s *Store) Driver() string {
	return DriverName
}

func withCircuitBreaker[T any](s *Store, baseFn, fallbackFn func() (T, error)) (T, error) {
	if s.circuitBreaker.State() == gobreaker.StateOpen {
		s.log.Debug("Calling overlay fallback method")
		return fallbackFn()
	}

	s.log.Debug("Calling overlay base method")
	result, err := s.circuitBreaker.Execute(func() (interface{}, error) {
		// TODO(saml) only increment on network specific errors?
		return baseFn()
	})

	//nolint:forcetypeassert
	return result.(T), err
}

func (s *Store) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	return withCircuitBreaker(
		s,
		func() (*runtimev1.RunnablePolicySet, error) { return s.basePolicyLoader.GetPolicySet(ctx, id) },
		func() (*runtimev1.RunnablePolicySet, error) { return s.fallbackPolicyLoader.GetPolicySet(ctx, id) },
	)
}

func (s *Store) ListPolicyIDs(ctx context.Context, includeDisabled bool) ([]string, error) {
	return withCircuitBreaker(
		s,
		func() ([]string, error) { return s.baseStore.ListPolicyIDs(ctx, includeDisabled) },
		func() ([]string, error) { return s.fallbackStore.ListPolicyIDs(ctx, includeDisabled) },
	)
}

func (s *Store) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return withCircuitBreaker(
		s,
		func() ([]string, error) { return s.baseStore.ListSchemaIDs(ctx) },
		func() ([]string, error) { return s.fallbackStore.ListSchemaIDs(ctx) },
	)
}

func (s *Store) LoadSchema(ctx context.Context, url string) (io.ReadCloser, error) {
	return withCircuitBreaker(
		s,
		func() (io.ReadCloser, error) { return s.baseStore.LoadSchema(ctx, url) },
		func() (io.ReadCloser, error) { return s.fallbackStore.LoadSchema(ctx, url) },
	)
}

func (s *Store) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return withCircuitBreaker(
		s,
		func() (map[namer.ModuleID]*policy.CompilationUnit, error) {
			return s.baseStore.GetCompilationUnits(ctx, ids...)
		},
		func() (map[namer.ModuleID]*policy.CompilationUnit, error) {
			return s.fallbackStore.GetCompilationUnits(ctx, ids...)
		},
	)
}

func (s *Store) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return withCircuitBreaker(
		s,
		func() (map[namer.ModuleID][]namer.ModuleID, error) { return s.baseStore.GetDependents(ctx, ids...) },
		func() (map[namer.ModuleID][]namer.ModuleID, error) { return s.fallbackStore.GetDependents(ctx, ids...) },
	)
}

func (s *Store) LoadPolicy(ctx context.Context, file ...string) ([]*policy.Wrapper, error) {
	return withCircuitBreaker(
		s,
		func() ([]*policy.Wrapper, error) { return s.baseStore.LoadPolicy(ctx, file...) },
		func() ([]*policy.Wrapper, error) { return s.fallbackStore.LoadPolicy(ctx, file...) },
	)
}
