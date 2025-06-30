// Copyright 2021-2025 Zenauth Ltd.
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
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	negativeCacheEntryTTL = 10 * time.Second
	storeFetchTimeout     = 2 * time.Second
	updateQueueSize       = 32
)

type Manager struct {
	store       storage.SourceStore
	schemaMgr   schema.Manager
	sf          singleflight.Group
	log         *zap.SugaredLogger
	updateQueue chan storage.Event
	*storage.SubscriptionManager
}

func NewManager(ctx context.Context, store storage.SourceStore, schemaMgr schema.Manager) (*Manager, error) {
	if err := config.GetSection(&Conf{}); err != nil {
		return nil, err
	}

	c := &Manager{
		log:                 zap.S().Named("compiler"),
		store:               store,
		schemaMgr:           schemaMgr,
		updateQueue:         make(chan storage.Event, updateQueueSize),
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}

	go c.processUpdateQueue(ctx)
	store.Subscribe(c)

	return c, nil
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
			case storage.EventReload, storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
				c.NotifySubscribers(evt)
			default:
				c.log.Debugw("Ignoring storage event", "event", evt)
			}
		}
	}
}

func (c *Manager) compile(unit *policy.CompilationUnit) (*runtimev1.RunnablePolicySet, error) {
	return metrics.RecordDuration2(metrics.CompileDuration(), func() (*runtimev1.RunnablePolicySet, error) {
		return Compile(unit, c.schemaMgr)
	})
}

func (c *Manager) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	if len(candidates) == 0 {
		return nil, errors.New("candidates list must contain at least one candidate")
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

func (c *Manager) GetAll(ctx context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	cus, err := c.store.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get compilation units: %w", err)
	}

	rpsSet := make([]*runtimev1.RunnablePolicySet, 0, len(cus))
	for _, cu := range cus {
		rps, err := c.compile(cu)
		if err != nil {
			return nil, PolicyCompilationErr{underlying: err}
		}

		if rps == nil {
			continue
		}

		rpsSet = append(rpsSet, rps)
	}

	return rpsSet, nil
}

func (c *Manager) GetPolicySet(ctx context.Context, modID namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	key := modID.String()
	defer c.sf.Forget(key)

	rpsVal, err, _ := c.sf.Do(key, func() (any, error) {
		compileUnits, err := c.store.GetCompilationUnits(ctx, modID)
		if err != nil {
			return nil, fmt.Errorf("failed to get compilation units: %w", err)
		}

		if len(compileUnits) == 0 {
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
