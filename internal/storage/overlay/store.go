// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"

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

	return &Store{
		conf:                conf,
		baseStore:           baseStore,
		fallbackStore:       fallbackStore,
		circuitBreaker:      createCircuitBreaker(conf),
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}, nil
}

func createCircuitBreaker(conf *Conf) *gobreaker.CircuitBreaker {
	breakerSettings := gobreaker.Settings{
		Name: "Store",
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures > uint32(conf.FailoverThreshold)
		},
		Interval: time.Duration(conf.FailoverIntervalMinutes) * time.Minute,
		Timeout:  0,
	}
	return gobreaker.NewCircuitBreaker(breakerSettings)
}

type Store struct {
	conf                 *Conf
	baseStore            storage.SourceStore
	fallbackStore        storage.SourceStore
	basePolicyLoader     engine.PolicyLoader
	fallbackPolicyLoader engine.PolicyLoader
	circuitBreaker       *gobreaker.CircuitBreaker
	*storage.SubscriptionManager
}

// GetOverlayPolicyLoader instantiates both the base and fallback policy loaders, and returns the base.
func (s *Store) GetOverlayPolicyLoader(ctx context.Context, schemaMgr schema.Manager) (engine.PolicyLoader, error) {
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

	return s.basePolicyLoader, nil
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) withCircuitBreaker(baseFn, fallbackFn func() (interface{}, error)) (interface{}, error) {
	if s.circuitBreaker.State() == gobreaker.StateOpen {
		return fallbackFn()
	}

	// TODO(saml) we only want to increment the circuitBreaker counter on relevant IO errors
	result, err := s.circuitBreaker.Execute(baseFn)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	result, err := s.withCircuitBreaker(
		func() (interface{}, error) {
			return s.basePolicyLoader.GetPolicySet(ctx, id)
		},
		func() (interface{}, error) {
			return s.fallbackPolicyLoader.GetPolicySet(ctx, id)
		},
	)
	if err != nil {
		return nil, err
	}

	rps, ok := result.(*runtimev1.RunnablePolicySet)
	if !ok {
		return nil, errors.New("error retrieving wrapped policy set")
	}
	return rps, nil
}

func (s *Store) ListPolicyIDs(ctx context.Context, includeDisabled bool) ([]string, error) {
	result, err := s.withCircuitBreaker(
		func() (interface{}, error) {
			return s.baseStore.ListPolicyIDs(ctx, includeDisabled)
		},
		func() (interface{}, error) {
			return s.fallbackStore.ListPolicyIDs(ctx, includeDisabled)
		},
	)
	if err != nil {
		return nil, err
	}

	ids, ok := result.([]string)
	if !ok {
		return nil, errors.New("error retrieving list policy IDs")
	}
	return ids, nil
}

func (s *Store) ListSchemaIDs(ctx context.Context) ([]string, error) {
	result, err := s.withCircuitBreaker(
		func() (interface{}, error) {
			return s.baseStore.ListSchemaIDs(ctx)
		},
		func() (interface{}, error) {
			return s.fallbackStore.ListSchemaIDs(ctx)
		},
	)
	if err != nil {
		return nil, err
	}

	ids, ok := result.([]string)
	if !ok {
		return nil, errors.New("error retrieving list schema IDs")
	}
	return ids, nil
}

func (s *Store) LoadSchema(ctx context.Context, url string) (io.ReadCloser, error) {
	result, err := s.withCircuitBreaker(
		func() (interface{}, error) {
			return s.baseStore.LoadSchema(ctx, url)
		},
		func() (interface{}, error) {
			return s.fallbackStore.LoadSchema(ctx, url)
		},
	)
	if err != nil {
		return nil, err
	}

	schema, ok := result.(io.ReadCloser)
	if !ok {
		return nil, errors.New("error retrieving schema")
	}
	return schema, nil
}

func (s *Store) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	result, err := s.withCircuitBreaker(
		func() (interface{}, error) {
			return s.baseStore.GetCompilationUnits(ctx, ids...)
		},
		func() (interface{}, error) {
			return s.fallbackStore.GetCompilationUnits(ctx, ids...)
		},
	)
	if err != nil {
		return nil, err
	}

	cu, ok := result.(map[namer.ModuleID]*policy.CompilationUnit)
	if !ok {
		return nil, errors.New("error retrieving compilation units")
	}
	return cu, nil
}

func (s *Store) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	result, err := s.withCircuitBreaker(
		func() (interface{}, error) {
			return s.baseStore.GetDependents(ctx, ids...)
		},
		func() (interface{}, error) {
			return s.fallbackStore.GetDependents(ctx, ids...)
		},
	)
	if err != nil {
		return nil, err
	}

	deps, ok := result.(map[namer.ModuleID][]namer.ModuleID)
	if !ok {
		return nil, errors.New("error retrieving dependents")
	}
	return deps, nil
}

func (s *Store) LoadPolicy(ctx context.Context, file ...string) ([]*policy.Wrapper, error) {
	result, err := s.withCircuitBreaker(
		func() (interface{}, error) {
			return s.baseStore.LoadPolicy(ctx, file...)
		},
		func() (interface{}, error) {
			return s.fallbackStore.LoadPolicy(ctx, file...)
		},
	)
	if err != nil {
		return nil, err
	}

	policies, ok := result.([]*policy.Wrapper)
	if !ok {
		return nil, errors.New("error retrieving policies")
	}
	return policies, nil
}
