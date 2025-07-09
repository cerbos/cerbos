// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sony/gobreaker/v2"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

const DriverName = "overlay"

var (
	_ Overlay             = (*Store)(nil)
	_ storage.BinaryStore = (*Store)(nil)
	_ storage.Reloadable  = (*Store)(nil)
)

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

	p := pool.New().WithContext(ctx).WithCancelOnError().WithFirstError()

	var baseStore, fallbackStore storage.Store
	p.Go(func(_ context.Context) error {
		var err error
		baseStore, err = getStore(conf.BaseDriver)
		if err != nil {
			return fmt.Errorf("failed to create base policy loader: %w", err)
		}
		return nil
	})

	p.Go(func(_ context.Context) error {
		var err error
		fallbackStore, err = getStore(conf.FallbackDriver)
		if err != nil {
			return fmt.Errorf("failed to create fallback policy loader: %w", err)
		}
		return nil
	})

	if err := p.Wait(); err != nil {
		return nil, err
	}

	return &Store{
		log:            logger,
		conf:           conf,
		baseStore:      baseStore,
		fallbackStore:  fallbackStore,
		circuitBreaker: newCircuitBreaker(conf),
	}, nil
}

type Store struct {
	log                  *zap.SugaredLogger
	conf                 *Conf
	baseStore            storage.Store
	fallbackStore        storage.Store
	basePolicyLoader     policyloader.PolicyLoader
	fallbackPolicyLoader policyloader.PolicyLoader
	circuitBreaker       *gobreaker.CircuitBreaker[any]
}

func newCircuitBreaker(conf *Conf) *gobreaker.CircuitBreaker[any] {
	breakerSettings := gobreaker.Settings{
		Name: "Store",
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= uint32(conf.FallbackErrorThreshold)
		},
		Interval: conf.FallbackErrorWindow,
		Timeout:  0,
	}
	return gobreaker.NewCircuitBreaker[any](breakerSettings)
}

// GetOverlayPolicyLoader instantiates both the base and fallback policy loaders and then returns itself.
func (s *Store) GetOverlayPolicyLoader(ctx context.Context, schemaMgr schema.Manager) (policyloader.PolicyLoader, error) {
	getPolicyLoader := func(storeInterface storage.Store) (policyloader.PolicyLoader, error) {
		switch st := storeInterface.(type) {
		case storage.SourceStore:
			pl, err := compile.NewManager(ctx, st, schemaMgr)
			if err != nil {
				return nil, fmt.Errorf("failed to create compile manager: %w", err)
			}
			return pl, nil
		case storage.BinaryStore:
			return st, nil
		default:
			return nil, errors.New("overlaid store does not implement either SourceStore or BinaryStore interfaces")
		}
	}

	var err error
	if s.basePolicyLoader, err = getPolicyLoader(s.baseStore); err != nil {
		return nil, err
	}
	if s.fallbackPolicyLoader, err = getPolicyLoader(s.fallbackStore); err != nil {
		return nil, err
	}

	return s, nil
}

func withCircuitBreaker[T any](s *Store, baseFn, fallbackFn func() (T, error)) (T, error) {
	if s.circuitBreaker.State() == gobreaker.StateOpen {
		s.log.Debug("Calling overlay fallback method")
		return fallbackFn()
	}

	s.log.Debug("Calling overlay base method")
	result, err := s.circuitBreaker.Execute(func() (any, error) {
		return baseFn()
	})

	//nolint:forcetypeassert
	return result.(T), err
}

//
// PolicyLoader interface
//

func (s *Store) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	return withCircuitBreaker(
		s,
		func() (*runtimev1.RunnablePolicySet, error) { return s.basePolicyLoader.GetFirstMatch(ctx, candidates) },
		func() (*runtimev1.RunnablePolicySet, error) {
			return s.fallbackPolicyLoader.GetFirstMatch(ctx, candidates)
		},
	)
}

func (s *Store) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	return withCircuitBreaker(
		s,
		func() ([]*runtimev1.RunnablePolicySet, error) { return s.basePolicyLoader.GetAllMatching(ctx, modIDs) },
		func() ([]*runtimev1.RunnablePolicySet, error) {
			return s.fallbackPolicyLoader.GetAllMatching(ctx, modIDs)
		},
	)
}

//
// Store interface methods
//

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetAll(ctx context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	return withCircuitBreaker(
		s,
		func() ([]*runtimev1.RunnablePolicySet, error) { return s.basePolicyLoader.GetAll(ctx) },
		func() ([]*runtimev1.RunnablePolicySet, error) {
			return s.fallbackPolicyLoader.GetAll(ctx)
		},
	)
}

func (s *Store) ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	return withCircuitBreaker(
		s,
		func() ([]string, error) { return s.baseStore.ListPolicyIDs(ctx, params) },
		func() ([]string, error) { return s.fallbackStore.ListPolicyIDs(ctx, params) },
	)
}

func (s *Store) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return withCircuitBreaker(
		s,
		func() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
			return s.baseStore.InspectPolicies(ctx, params)
		},
		func() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
			return s.fallbackStore.InspectPolicies(ctx, params)
		},
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

func (s *Store) Reload(ctx context.Context) error {
	// We attempt to reload all stores in parallel, regardless of base/fallback configuration.
	// Attempts on non-Reloadable stores will result in a noop.
	p := pool.New().WithContext(ctx).WithCancelOnError().WithFirstError()

	if bs, ok := s.baseStore.(storage.Reloadable); ok {
		p.Go(func(ctx context.Context) error { return bs.Reload(ctx) })
	}

	if fs, ok := s.fallbackStore.(storage.Reloadable); ok {
		p.Go(func(ctx context.Context) error { return fs.Reload(ctx) })
	}

	return p.Wait()
}

func (s *Store) Subscribe(subscriber storage.Subscriber) {
	if bs, ok := s.baseStore.(storage.Subscribable); ok {
		bs.Subscribe(subscriber)
	}

	if fs, ok := s.fallbackStore.(storage.Subscribable); ok {
		fs.Subscribe(subscriber)
	}
}

func (s *Store) Unsubscribe(subscriber storage.Subscriber) {
	if bs, ok := s.baseStore.(storage.Subscribable); ok {
		bs.Unsubscribe(subscriber)
	}

	if fs, ok := s.fallbackStore.(storage.Subscribable); ok {
		fs.Unsubscribe(subscriber)
	}
}

func (s *Store) Close() (outErr error) {
	if c, ok := s.baseStore.(io.Closer); ok {
		outErr = multierr.Append(outErr, c.Close())
	}

	if c, ok := s.fallbackStore.(io.Closer); ok {
		outErr = multierr.Append(outErr, c.Close())
	}

	return outErr
}
