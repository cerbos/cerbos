// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"errors"
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

var (
	_ Overlay             = (*Store)(nil)
	_ storage.BinaryStore = (*Store)(nil)
	_ storage.Reloadable  = (*Store)(nil)
	_ storage.SourceStore = (*Store)(nil)
)

var errFallbackMethodNotImplemented = errors.New("fallback store does not implement method")

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
	getStore := func(key string) (storage.Store, error) {
		cons, err := storage.GetDriverConstructor(key)
		if err != nil {
			return nil, fmt.Errorf("unknown storage driver [%s]", key)
		}

		store, err := cons(ctx, confW)
		if err != nil {
			return nil, fmt.Errorf("failed to create overlay store: %w", err)
		}

		return store, nil
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
	baseStore            storage.Store
	fallbackStore        storage.Store
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
	getPolicyLoader := func(storeInterface storage.Store, key string) (engine.PolicyLoader, error) {
		switch st := storeInterface.(type) {
		case storage.SourceStore:
			pl, err := compile.NewManager(ctx, st, schemaMgr)
			if err != nil {
				s.log.Errorw(fmt.Sprintf("Failed to create %s compile manager", key), "error", err)
				return nil, fmt.Errorf("failed to create %s compile manager: %w", key, err)
			}
			return pl, nil
		case storage.BinaryStore:
			return st, nil
		default:
			return nil, errors.New("overlaid store does not implement either SourceStore or BinaryStore interfaces")
		}
	}

	var err error
	if s.basePolicyLoader, err = getPolicyLoader(s.baseStore, "base"); err != nil {
		return nil, err
	}
	if s.fallbackPolicyLoader, err = getPolicyLoader(s.fallbackStore, "fallback"); err != nil {
		return nil, err
	}

	return s, nil
}

func getTypedStores[T any](baseStore, fallbackStore storage.Store) (baseResult, fallbackResult T, err error) {
	bs, ok := baseStore.(T)
	if !ok {
		return baseResult, fallbackResult, errors.New("store interface does not implement method")
	}
	fs, ok := fallbackStore.(T)
	if !ok {
		return bs, fallbackResult, errFallbackMethodNotImplemented
	}
	return bs, fs, nil
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

//
// PolicyLoader interface
//

func (s *Store) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	// Both `SourceStore` (via `compile.Manager`) and `BinaryStore` implement GetPolicySet
	return withCircuitBreaker(
		s,
		func() (*runtimev1.RunnablePolicySet, error) { return s.basePolicyLoader.GetPolicySet(ctx, id) },
		func() (*runtimev1.RunnablePolicySet, error) { return s.fallbackPolicyLoader.GetPolicySet(ctx, id) },
	)
}

//
// Store interface methods
//

func (s *Store) Driver() string {
	return DriverName
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

//
// SourceStore interface methods
//

func (s *Store) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	bs, fs, err := getTypedStores[storage.SourceStore](s.baseStore, s.fallbackStore)
	if err != nil {
		if errors.Is(err, errFallbackMethodNotImplemented) {
			return bs.GetCompilationUnits(ctx, ids...)
		}
		return nil, err
	}

	return withCircuitBreaker(
		s,
		func() (map[namer.ModuleID]*policy.CompilationUnit, error) {
			return bs.GetCompilationUnits(ctx, ids...)
		},
		func() (map[namer.ModuleID]*policy.CompilationUnit, error) {
			return fs.GetCompilationUnits(ctx, ids...)
		},
	)
}

func (s *Store) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	bs, fs, err := getTypedStores[storage.SourceStore](s.baseStore, s.fallbackStore)
	if err != nil {
		if errors.Is(err, errFallbackMethodNotImplemented) {
			return bs.GetDependents(ctx, ids...)
		}
		return nil, err
	}

	return withCircuitBreaker(
		s,
		func() (map[namer.ModuleID][]namer.ModuleID, error) { return bs.GetDependents(ctx, ids...) },
		func() (map[namer.ModuleID][]namer.ModuleID, error) { return fs.GetDependents(ctx, ids...) },
	)
}

func (s *Store) LoadPolicy(ctx context.Context, file ...string) ([]*policy.Wrapper, error) {
	bs, fs, err := getTypedStores[storage.SourceStore](s.baseStore, s.fallbackStore)
	if err != nil {
		if errors.Is(err, errFallbackMethodNotImplemented) {
			return bs.LoadPolicy(ctx, file...)
		}
		return nil, err
	}

	return withCircuitBreaker(
		s,
		func() ([]*policy.Wrapper, error) { return bs.LoadPolicy(ctx, file...) },
		func() ([]*policy.Wrapper, error) { return fs.LoadPolicy(ctx, file...) },
	)
}

//
// Reloadable interface methods
//

func (s *Store) Reload(ctx context.Context) error {
	bs, fs, err := getTypedStores[storage.Reloadable](s.baseStore, s.fallbackStore)
	if err != nil {
		if errors.Is(err, errFallbackMethodNotImplemented) {
			return bs.Reload(ctx)
		}
		return err
	}

	placeholderFn := func(ctx context.Context, fn func(context.Context) error) (struct{}, error) {
		err := fn(ctx)
		return struct{}{}, err
	}
	_, err = withCircuitBreaker(
		s,
		func() (struct{}, error) { return placeholderFn(ctx, bs.Reload) },
		func() (struct{}, error) { return placeholderFn(ctx, fs.Reload) },
	)
	return err
}
