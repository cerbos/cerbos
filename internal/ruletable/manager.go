// Copyright 2021-2025 Zenauth Ltd.
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
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

type Manager struct {
	*RuleTable
	policyLoader policyloader.PolicyLoader
	schemaLoader schema.Loader
	log          *logging.Logger
	mu           sync.RWMutex
}

func NewRuleTableManager(protoRT *runtimev1.RuleTable, policyLoader policyloader.PolicyLoader, schemaLoader schema.Loader, schemaMgr schema.Manager) (*Manager, error) {
	conf, err := evaluator.GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read engine configuration: %w", err)
	}

	rt := &RuleTable{
		conf:      conf,
		schemaMgr: schemaMgr,
	}

	if err := rt.init(protoRT); err != nil {
		return nil, err
	}

	return &Manager{
		log:          logging.NewLogger("ruletable"),
		RuleTable:    rt,
		policyLoader: policyLoader,
		schemaLoader: schemaLoader,
	}, nil
}

func (mgr *Manager) Check(ctx context.Context, tctx tracer.Context, evalParams evaluator.EvalParams, input *enginev1.CheckInput) (*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.checkWithAuditTrail(ctx, tctx, evalParams, input)
}

func (mgr *Manager) Plan(ctx context.Context, input *enginev1.PlanResourcesInput, principalVersion, resourceVersion string, nowFunc conditions.NowFunc, globals map[string]any) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.planWithAuditTrail(ctx, input, principalVersion, resourceVersion, nowFunc, globals)
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

	ctx, cancelFunc := context.WithTimeout(context.Background(), mgr.conf.PolicyLoaderTimeout)
	defer cancelFunc()

	mgr.log.Info("Reloading rule table")
	rt := NewProtoRuletable()

	// If compilation fails, maintain the last valid rule table state.
	// Set isStale to false to prevent repeated recompilation attempts until new events arrive.
	if err := LoadPolicies(ctx, rt, mgr.policyLoader); err != nil {
		return fmt.Errorf("rule table compilation failed, using previous valid state: %w", err)
	}

	if err := mgr.init(rt); err != nil {
		return err
	}

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
		mgr.deletePolicy(evt.PolicyID)
		if evt.OldPolicyID != nil {
			mgr.deletePolicy(*evt.OldPolicyID)
		}

		if rps != nil {
			if err = mgr.addPolicy(rps); err != nil {
				return err
			}
		}
	case storage.EventDeleteOrDisablePolicy:
		mgr.deletePolicy(evt.PolicyID)
	}

	if len(evt.Dependents) > 0 {
		// handle reloading dependents atomically
		toReload, err := mgr.policyLoader.GetAllMatching(ctx, evt.Dependents)
		if err != nil {
			return fmt.Errorf("failed to load dependent policies: %w", err)
		}

		// we leave ruletable state static until we're sure all dependents are valid, and then update
		for _, modID := range evt.Dependents {
			mgr.deletePolicy(modID)
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

func (mgr *Manager) deletePolicy(moduleID namer.ModuleID) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.doDeletePolicy(moduleID)
}

// doDeletePolicy implements the delete logic. The caller must obtain a lock first.
func (mgr *Manager) doDeletePolicy(moduleID namer.ModuleID) {
	meta := mgr.Meta[moduleID.RawValue()]
	if meta == nil {
		return
	}

	mgr.log.Debugf("Deleting policy %s", meta.GetFqn())

	for version, scopeMap := range mgr.primaryIdx {
		for scope, roleMap := range scopeMap {
			scopedParentRoleAncestors := mgr.parentRoleAncestors[scope]

			for role, actionMap := range roleMap.GetAll() {
				for action, rules := range actionMap.GetAll() {
					newRules := make([]*Row, 0, len(rules))
					for _, r := range rules {
						if r.OriginFqn != meta.GetFqn() {
							newRules = append(newRules, r)
						} else {
							mgr.log.Debugf("Dropping rule %s", r.GetOriginFqn())
						}
					}

					if len(newRules) > 0 {
						actionMap.Set(action, newRules)
					} else {
						actionMap.DeleteLiteral(action)
					}
				}

				if actionMap.Len() == 0 {
					roleMap.DeleteLiteral(role)
					delete(scopedParentRoleAncestors, role)
				}
			}

			if roleMap.Len() == 0 {
				delete(scopeMap, scope)
				delete(mgr.principalScopeMap, scope)
				delete(mgr.resourceScopeMap, scope)
				delete(mgr.scopeScopePermissions, scope)
				delete(mgr.parentRoleAncestors, scope)
			}
		}

		if len(scopeMap) == 0 {
			delete(mgr.primaryIdx, version)
		}
	}

	delete(mgr.Schemas, moduleID.RawValue())
	delete(mgr.Meta, moduleID.RawValue())
	delete(mgr.policyDerivedRoles, moduleID)
}
