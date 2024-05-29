// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/cache"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/rolepolicy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	negativeCacheEntryTTL = 10 * time.Second
	storeFetchTimeout     = 2 * time.Second
	updateQueueSize       = 32
)

type Manager struct {
	log           *zap.SugaredLogger
	store         storage.SourceStore
	schemaMgr     schema.Manager
	updateQueue   chan storage.Event
	cache         *cache.Cache[namer.ModuleID, *runtimev1.RunnablePolicySet]
	sf            singleflight.Group
	cacheDuration time.Duration
}

func NewManager(ctx context.Context, store storage.SourceStore, schemaMgr schema.Manager) (*Manager, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, err
	}

	return NewManagerFromConf(ctx, conf, store, schemaMgr), nil
}

func NewManagerFromDefaultConf(ctx context.Context, store storage.SourceStore, schemaMgr schema.Manager) *Manager {
	return NewManagerFromConf(ctx, DefaultConf(), store, schemaMgr)
}

func NewManagerFromConf(ctx context.Context, conf *Conf, store storage.SourceStore, schemaMgr schema.Manager) *Manager {
	c := &Manager{
		log:           zap.S().Named("compiler"),
		store:         store,
		schemaMgr:     schemaMgr,
		updateQueue:   make(chan storage.Event, updateQueueSize),
		cache:         cache.New[namer.ModuleID, *runtimev1.RunnablePolicySet]("compile", conf.CacheSize),
		cacheDuration: conf.CacheDuration,
	}

	go c.processUpdateQueue(ctx)
	store.Subscribe(c)

	return c
}

func (c *Manager) SubscriberID() string {
	return "compile.Manager"
}

func (c *Manager) OnStorageEvent(events ...storage.Event) {
	for _, evt := range events {
		c.log.Debugw("Received storage event", "event", evt)
		c.updateQueue <- evt
	}
}

func (c *Manager) processUpdateQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-c.updateQueue:
			c.log.Debugw("Processing storage event", "event", evt)
			switch evt.Kind {
			case storage.EventReload:
				c.log.Info("Purging compile cache")
				c.cache.Purge()
			case storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
				if err := c.recompile(evt); err != nil {
					c.log.Warnw("Error while processing storage event", "event", evt, "error", err)
				}
			default:
				c.log.Debugw("Ignoring storage event", "event", evt)
			}
		}
	}
}

func (c *Manager) recompile(evt storage.Event) error {
	// if this is a delete event, remove the module from the cache
	if evt.Kind == storage.EventDeleteOrDisablePolicy {
		c.evict(evt.PolicyID)
	}

	// find the modules that will be affected by this policy getting updated or deleted.
	var toRecompile []namer.ModuleID
	if evt.Kind == storage.EventAddOrUpdatePolicy {
		toRecompile = append(toRecompile, evt.PolicyID)

		// if the policy ID has changed, remove the old cached entry
		if evt.OldPolicyID != nil {
			c.evict(*evt.OldPolicyID)
		}
	}

	dependents, err := c.getDependents(evt.PolicyID)
	if err != nil {
		return err
	}

	// only recompile the ones that are already cached.
	for _, d := range dependents {
		if c.cache.Has(d) {
			toRecompile = append(toRecompile, d)
		}
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), storeFetchTimeout)
	defer cancelFunc()

	compileUnits, err := c.store.GetCompilationUnits(ctx, toRecompile...)
	if err != nil {
		return fmt.Errorf("failed to get compilation units: %w", err)
	}

	for modID, cu := range compileUnits {
		if cu.MainPolicy() == nil || cu.MainPolicy().Disabled {
			c.evict(cu.ModID)
			c.log.Debugw("Evicted the disabled policy", "id", cu.ModID.String())
			continue
		}
		if _, err := c.compile(cu); err != nil {
			// log and remove the module that failed to compile.
			c.log.Errorw("Failed to recompile", "id", modID, "error", err)
			c.evict(modID)
		}
	}

	return nil
}

func (c *Manager) getDependents(modID namer.ModuleID) ([]namer.ModuleID, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), storeFetchTimeout)
	defer cancelFunc()

	dependents, err := c.store.GetDependents(ctx, modID)
	if err != nil {
		return nil, fmt.Errorf("failed to find dependents: %w", err)
	}

	if len(dependents) > 0 {
		return dependents[modID], nil
	}

	return nil, nil
}

func (c *Manager) compile(unit *policy.CompilationUnit) (*runtimev1.RunnablePolicySet, error) {
	rps, err := metrics.RecordDuration2(metrics.CompileDuration(), func() (*runtimev1.RunnablePolicySet, error) {
		return Compile(unit, c.schemaMgr, rolepolicy.NewNopManager())
	})
	if err == nil && rps != nil {
		if c.cacheDuration > 0 {
			c.cache.SetWithExpire(unit.ModID, rps, c.cacheDuration)
		} else {
			c.cache.Set(unit.ModID, rps)
		}
	}

	return rps, err
}

func (c *Manager) evict(modID namer.ModuleID) {
	c.cache.Remove(modID)
}

func (c *Manager) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	if len(candidates) == 0 {
		return nil, errors.New("candidates list must contain at least one candidate")
	}

	// If the first candidate is not in the cache, we need to fallback to the store to avoid false positive cache hits when lenient scope search is enabled.
	if rps, ok := c.cache.Get(candidates[0]); ok && rps != nil {
		return rps, nil
	}

	key := candidates[0].String()
	defer c.sf.Forget(key)

	rpsVal, err, _ := c.sf.Do(key, func() (any, error) {
		cu, err := c.store.GetFirstMatch(ctx, candidates)
		if err != nil {
			return nil, fmt.Errorf("failed to get compilation units: %w", err)
		}

		if cu == nil {
			return nil, nil
		}

		rps, err := c.compile(cu)
		if err != nil {
			return nil, PolicyCompilationErr{underlying: err}
		}

		return rps, nil
	})
	if err != nil {
		return nil, err
	}

	if rpsVal == nil {
		return nil, nil
	}

	//nolint:forcetypeassert
	return rpsVal.(*runtimev1.RunnablePolicySet), nil
}

func (c *Manager) GetPolicySet(ctx context.Context, modID namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	key := modID.String()
	defer c.sf.Forget(key)

	rpsVal, err, _ := c.sf.Do(key, func() (any, error) {
		rps, ok := c.cache.Get(modID)
		if ok {
			return rps, nil
		}

		compileUnits, err := c.store.GetCompilationUnits(ctx, modID)
		if err != nil {
			return nil, fmt.Errorf("failed to get compilation units: %w", err)
		}

		if len(compileUnits) == 0 {
			// store a nil value in the cache as a negative entry to prevent hitting the database again and again
			c.cache.SetWithExpire(modID, nil, negativeCacheEntryTTL)
			return nil, nil
		}

		var retVal *runtimev1.RunnablePolicySet
		for mID, cu := range compileUnits {
			rps, err := c.compile(cu)
			if err != nil {
				return nil, PolicyCompilationErr{underlying: err}
			}

			if mID == modID {
				retVal = rps
			}
		}

		return retVal, nil
	})
	if err != nil {
		return nil, err
	}

	if rpsVal == nil {
		return nil, nil
	}

	//nolint:forcetypeassert
	return rpsVal.(*runtimev1.RunnablePolicySet), nil
}

type PolicyCompilationErr struct {
	underlying error
}

func (pce PolicyCompilationErr) Error() string {
	return fmt.Sprintf("policy compilation error: %v", pce.underlying)
}

func (pce PolicyCompilationErr) Unwrap() error {
	return pce.underlying
}

func (pce PolicyCompilationErr) Is(target error) bool {
	return errors.As(target, &PolicyCompilationErr{})
}
