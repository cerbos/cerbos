// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

import (
	"context"
	"fmt"
	"sync"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

type Manager struct {
	*RuleTable
	conf         *evaluator.Conf
	policyLoader policyloader.PolicyLoader
	schemaMgr    schema.Manager
	log          *logging.Logger
	mu           sync.RWMutex
}

func NewRuleTableManager(ruleTable *RuleTable, policyLoader policyloader.PolicyLoader, schemaMgr schema.Manager) (*Manager, error) {
	conf, err := evaluator.GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read engine configuration: %w", err)
	}

	return &Manager{
		conf:         conf,
		log:          logging.NewLogger("ruletable"),
		policyLoader: policyLoader,
		schemaMgr:    schemaMgr,
		RuleTable:    ruleTable,
	}, nil
}

func (mgr *Manager) Check(ctx context.Context, tctx tracer.Context, evalParams evaluator.EvalParams, input *enginev1.CheckInput) (*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.checkWithAuditTrail(ctx, tctx, mgr.schemaMgr, evalParams, input)
}

func (mgr *Manager) Plan(ctx context.Context, input *enginev1.PlanResourcesInput, principalScope, principalVersion, resourceScope, resourceVersion string, nowFunc conditions.NowFunc, globals map[string]any, lenientScopeSearch bool) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.planWithAuditTrail(ctx, mgr.schemaMgr, input, principalScope, principalVersion, resourceScope, resourceVersion, nowFunc, globals, lenientScopeSearch)
}

func (mgr *Manager) SubscriberID() string {
	return "engine.RuleTable"
}

func (mgr *Manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		switch event.Kind {
		case storage.EventReload:
			if err := mgr.reload(); err != nil {
				mgr.log.Warnw("Error reloading rule table, maintaining last valid state", "error", err)
			}
		case storage.EventAddOrUpdatePolicy, storage.EventDeleteOrDisablePolicy:
			mgr.log.Debugw("Processing storage event", "event", event)
			if err := mgr.processPolicyEvent(event); err != nil {
				mgr.log.Warnw("Error processing storage event, maintaining last valid state", "event", event, "error", err)
			}
		default:
			mgr.log.Debugw("Ignoring storage event", "event", event)
		}
	}
}

func (mgr *Manager) reload() error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var newRuleTable *RuleTable
	if ruleTableStore, ok := mgr.policyLoader.(RuleTableStore); ok {
		var err error
		newRuleTable, err = ruleTableStore.GetRuleTable()
		if err != nil {
			return fmt.Errorf("failed to load the new rule table: %w", err)
		}
	} else {
		ctx, cancelFunc := context.WithTimeout(context.Background(), mgr.conf.PolicyLoaderTimeout)
		defer cancelFunc()

		mgr.log.Info("Reloading rule table")
		protoRT := NewProtoRuletable()

		// If compilation fails, maintain the last valid rule table state.
		// Set isStale to false to prevent repeated recompilation attempts until new events arrive.
		if err := LoadPolicies(ctx, protoRT, mgr.policyLoader); err != nil {
			return fmt.Errorf("rule table compilation failed, using previous valid state: %w", err)
		}

		var err error
		if newRuleTable, err = NewRuleTable(index.NewMem(), protoRT); err != nil {
			return fmt.Errorf("failed to create rule table: %w", err)
		}
	}

	mgr.RuleTable = newRuleTable
	mgr.log.Info("Rule table reload successful")

	return nil
}

func (mgr *Manager) processPolicyEvent(evt storage.Event) (err error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), mgr.conf.PolicyLoaderTimeout)
	defer cancelFunc()

	switch evt.Kind { //nolint:exhaustive
	case storage.EventAddOrUpdatePolicy:
		var rps *runtimev1.RunnablePolicySet
		rps, err = mgr.policyLoader.GetFirstMatch(ctx, []namer.ModuleID{evt.PolicyID})
		if err != nil {
			return fmt.Errorf("failed to load policy: %w", err)
		}

		// Only delete if we successfully retrieved the policy above (e.g. no compilation errors occurred)
		if err := mgr.deletePolicy(evt.PolicyID); err != nil {
			return fmt.Errorf("failed to delete policy: %w", err)
		}
		if evt.OldPolicyID != nil {
			if err := mgr.deletePolicy(*evt.OldPolicyID); err != nil {
				return fmt.Errorf("failed to delete old policy: %w", err)
			}
		}

		if rps != nil {
			if err = mgr.addPolicy(rps); err != nil {
				return err
			}
		}
	case storage.EventDeleteOrDisablePolicy:
		if err := mgr.deletePolicy(evt.PolicyID); err != nil {
			return fmt.Errorf("failed to delete policy: %w", err)
		}
	}

	if len(evt.Dependents) > 0 {
		// handle reloading dependents atomically
		toReload, err := mgr.policyLoader.GetAllMatching(ctx, evt.Dependents)
		if err != nil {
			return fmt.Errorf("failed to load dependent policies: %w", err)
		}

		// we leave ruletable state static until we're sure all dependents are valid, and then update
		for _, modID := range evt.Dependents {
			if err := mgr.deletePolicy(modID); err != nil {
				mgr.log.Errorf("Failed to delete dependent: %w", err)
			}
		}

		for _, rps := range toReload {
			if err = mgr.addPolicy(rps); err != nil {
				return err
			}
		}
	}

	return nil
}

func (mgr *Manager) addPolicy(rps *runtimev1.RunnablePolicySet) error {
	if rps == nil {
		return nil
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if err := mgr.indexRules(AddPolicy(mgr.RuleTable.RuleTable, rps)); err != nil {
		return fmt.Errorf("failed to index and purge rules: %w", err)
	}

	return nil
}

func (mgr *Manager) deletePolicy(moduleID namer.ModuleID) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	return mgr.doDeletePolicy(moduleID)
}

// doDeletePolicy implements the delete logic. The caller must obtain a lock first.
func (mgr *Manager) doDeletePolicy(moduleID namer.ModuleID) error {
	meta := mgr.Meta[moduleID.RawValue()]
	if meta == nil {
		return nil
	}

	mgr.programCache.Clear()

	mgr.log.Debugf("Deleting policy %s", meta.GetFqn())

	ctx, cancelFn := context.WithTimeout(context.Background(), indexTimeout)
	defer cancelFn()

	activeScopes, err := mgr.idx.GetScopes(ctx)
	if err != nil {
		return err
	}
	activeScopeSet := make(map[string]struct{}, len(activeScopes))
	for _, s := range activeScopes {
		activeScopeSet[s] = struct{}{}
	}

	if err := mgr.idx.DeletePolicy(ctx, meta.GetFqn(), activeScopeSet); err != nil {
		return err
	}

	// TODO(saml) many of these ephemeral caches on the RuleTable should probably now reside inside the Index layer (for example: we shouldn't have to pass `activeScopes` to `idx.DeletePolicy`. That function should carry out all of this housekeeping).
	for scope := range mgr.principalScopeMap {
		if _, ok := activeScopeSet[scope]; !ok {
			delete(mgr.principalScopeMap, scope)
		}
	}

	for scope := range mgr.resourceScopeMap {
		if _, ok := activeScopeSet[scope]; !ok {
			delete(mgr.resourceScopeMap, scope)
		}
	}

	for scope := range mgr.scopeScopePermissions {
		if _, ok := activeScopeSet[scope]; !ok {
			delete(mgr.scopeScopePermissions, scope)
		}
	}

	delete(mgr.Schemas, moduleID.RawValue())
	delete(mgr.Meta, moduleID.RawValue())
	delete(mgr.policyDerivedRoles, moduleID)

	return nil
}
