// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	maxCacheSize          = 128
	negativeCacheEntryTTL = 10 * time.Second
)

type Manager struct {
	log         *zap.SugaredLogger
	store       storage.Store
	updateQueue chan storage.Event
	cache       gcache.Cache
}

func NewManager(ctx context.Context, store storage.Store) *Manager {
	c := &Manager{
		log:         zap.S().Named("compiler"),
		store:       store,
		updateQueue: make(chan storage.Event, updateQueueSize),
		cache:       gcache.New(maxCacheSize).ARC().Build(),
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
			if err := c.recompile(evt); err != nil {
				c.log.Warnw("Error while processing storage event", "event", evt, "error", err)
			}
		}
	}
}

func (c *Manager) recompile(evt storage.Event) error {
	// if this is a delete event, remove the module from the cache
	if evt.Kind == storage.EventDeletePolicy {
		c.evict(evt.PolicyID)
	}

	// find the modules that will be affected by this policy getting updated or deleted.
	var toRecompile []namer.ModuleID
	if evt.Kind == storage.EventAddOrUpdatePolicy {
		toRecompile = append(toRecompile, evt.PolicyID)
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

func (c *Manager) compile(unit *policy.CompilationUnit) (Evaluator, error) {
	startTime := time.Now()
	eval, err := Compile(unit)
	durationMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	if err == nil && eval != nil {
		_ = c.cache.Set(unit.ModID, eval)
	}

	status := "success"
	if err != nil {
		status = "failure"
	}

	_ = stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{tag.Upsert(metrics.KeyCompileStatus, status)},
		metrics.CompileDuration.M(durationMs),
	)

	return eval, err
}

func (c *Manager) evict(modID namer.ModuleID) {
	c.cache.Remove(modID)
}

func (c *Manager) GetEvaluator(ctx context.Context, modID namer.ModuleID) (Evaluator, error) {
	eval, err := c.cache.GetIFPresent(modID)
	if err == nil {
		// If the value is nil, it indicates a negative cache entry (see below)
		// Essentially, we tried to find this evaluator before and it wasn't found.
		// We don't want to hit the store over and over again because we know it doesn't exist.
		if eval == nil {
			return nil, nil
		}
		return eval.(Evaluator), nil
	}

	compileUnits, err := c.store.GetCompilationUnits(ctx, modID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compilation units: %w", err)
	}

	if len(compileUnits) == 0 {
		// store a nil value in the cache as a negative entry to prevent hitting the database again and again
		_ = c.cache.SetWithExpire(modID, nil, negativeCacheEntryTTL)
		return nil, nil
	}

	var retVal Evaluator
	for mID, cu := range compileUnits {
		eval, err := c.compile(cu)
		if err != nil {
			return nil, fmt.Errorf("failed to compile module %w", err)
		}

		if mID == modID {
			retVal = eval
		}
	}

	return retVal, nil
}
