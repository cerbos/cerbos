// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"sync"
	"sync/atomic"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"go.uber.org/zap"
)

type Manager struct {
	*RuleTable
	log          *zap.SugaredLogger
	mu           sync.RWMutex
	policyLoader policyloader.PolicyLoader
	// schemaMgr                  schema.Manager
	ruleTable                  *runtimev1.RuleTable
	isStale                    atomic.Bool
	awaitingHealthyPolicyStore atomic.Bool
}

func NewRuleTableManager(rt *runtimev1.RuleTable, policyLoader policyloader.PolicyLoader, schemaMgr schema.Manager) (*Manager, error) {
	manager, err := NewRuleTable(rt, schemaMgr)
	if err != nil {
		return nil, err
	}

	return &Manager{
		log:          zap.S().Named("ruletable"),
		RuleTable:    manager,
		policyLoader: policyLoader,
		ruleTable:    rt,
	}, nil
}

func (mgr *Manager) Check(ctx context.Context, tctx tracer.Context, evalParams EvalParams, input *enginev1.CheckInput) (*PolicyEvalResult, error) {
	if err := mgr.reload(ctx); err != nil {
		return nil, err
	}

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.RuleTable.Check(ctx, tctx, evalParams, input)
}

func (mgr *Manager) Plan(ctx context.Context, input *enginev1.PlanResourcesInput, principalVersion, resourceVersion string, nowFunc conditions.NowFunc, globals map[string]any) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	if err := mgr.reload(ctx); err != nil {
		return nil, nil, err
	}

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.RuleTable.Plan(ctx, input, principalVersion, resourceVersion, nowFunc, globals)
}

func (mgr *Manager) SubscriberID() string {
	return "engine.RuleTable"
}

func (mgr *Manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		switch event.Kind {
		case storage.EventReload:
			mgr.isStale.Store(true)
		case storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
			mgr.isStale.Store(true)
		}
	}
}

// TODO(saml) remove this post patching
func (mgr *Manager) reload(ctx context.Context) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if !mgr.isStale.Load() {
		// TODO(saml) this atomic bool is only used for logging purposes. Remove with patching
		if mgr.awaitingHealthyPolicyStore.Load() {
			mgr.log.Debug("Policy store invalid, using previous valid state")
		}
		return nil
	}

	mgr.log.Info("Reloading rule table")
	rt := NewProtoRuletable()

	// If compilation fails, maintain the last valid rule table state.
	// Set isStale to false to prevent repeated recompilation attempts until new events arrive.
	if err := LoadFromPolicyLoader(ctx, rt, mgr.policyLoader); err != nil {
		mgr.log.Errorf("Rule table compilation failed, using previous valid state: %v", err)
		mgr.isStale.Store(false)
		mgr.awaitingHealthyPolicyStore.Store(true)
		return nil
	}

	if err := mgr.load(rt); err != nil {
		return err
	}

	mgr.isStale.Store(false)
	mgr.awaitingHealthyPolicyStore.Store(false)

	return nil
}
