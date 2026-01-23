// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/cerbos/cerbos/internal/audit"
	audithub "github.com/cerbos/cerbos/internal/audit/hub"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	internalSchema "github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	storagehub "github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/storage/overlay"
	"github.com/cerbos/cerbos/internal/svc"
)

// CoreComponents holds the shared components needed for both server and Lambda function initialization.
type CoreComponents struct {
	Engine     *engine.Engine
	AuxData    *auxdata.AuxData
	AuditLog   audit.Log
	Store      storage.Store
	ReqLimits  svc.RequestLimits
	SuggestHub bool
}

// InitializeCerbosCore performs the common initialization steps shared between server and Lambda function.
func InitializeCerbosCore(ctx context.Context) (*CoreComponents, error) {
	// create audit log
	auditLog, err := audit.NewLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log: %w", err)
	}

	mdExtractor, err := audit.NewMetadataExtractor()
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata extractor: %w", err)
	}

	// create store
	store, err := storage.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	var policyLoader policyloader.PolicyLoader
	var ruleTableStore ruletable.RuleTableStore
	switch st := store.(type) {
	// Overlay needs to take precedence over BinaryStore in this type switch,
	// as our overlay store implements BinaryStore also
	case overlay.Overlay:
		// create wrapped policy loader
		pl, err := st.GetOverlayPolicyLoader(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create overlay policy loader: %w", err)
		}
		policyLoader = pl
	case storage.BinaryStore:
		policyLoader = st
		if rtStore, ok := store.(ruletable.RuleTableStore); ok {
			ruleTableStore = rtStore
		}
	case storage.SourceStore:
		// create compile manager
		policyLoader, err = compile.NewManager(ctx, st)
		if err != nil {
			return nil, fmt.Errorf("failed to create compile manager: %w", err)
		}
	default:
		return nil, ErrInvalidStore
	}

	evalConf, err := evaluator.GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read engine configuration: %w", err)
	}

	var ruleTable *ruletable.RuleTable
	//nolint:nestif
	if ruleTableStore != nil {
		rt, err := ruleTableStore.GetRuleTable()
		if err != nil {
			if !errors.Is(err, storagehub.ErrUnsupportedOperation) {
				return nil, fmt.Errorf("failed to load rule table: %w", err)
			}

			if ruleTable, err = ruletable.NewRuleTableFromLoader(ctx, policyLoader, evalConf.DefaultPolicyVersion); err != nil {
				return nil, fmt.Errorf("failed to create rule table from loader: %w", err)
			}
		} else {
			ruleTable = rt
		}
	} else {
		if ruleTable, err = ruletable.NewRuleTableFromLoader(ctx, policyLoader, evalConf.DefaultPolicyVersion); err != nil {
			return nil, fmt.Errorf("failed to create rule table from loader: %w", err)
		}
	}

	schemaMgr, err := internalSchema.New(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("failed to create schema manager: %w", err)
	}

	ruletableMgr, err := ruletable.NewRuleTableManagerFromConf(ruleTable, policyLoader, schemaMgr, evalConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create ruletable manager: %w", err)
	}

	if ss, ok := store.(storage.Subscribable); ok {
		ss.Subscribe(ruletableMgr)
	}

	// create engine
	eng, err := engine.New(ctx, engine.Components{
		PolicyLoader:      policyLoader,
		RuleTableManager:  ruletableMgr,
		SchemaMgr:         schemaMgr,
		AuditLog:          auditLog,
		MetadataExtractor: mdExtractor,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create engine: %w", err)
	}

	// initialize aux data
	auxData, err := auxdata.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auxData handler: %w", err)
	}

	serverConf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to get server configuration: %w", err)
	}

	reqLimits := svc.RequestLimits{
		MaxActionsPerResource:  serverConf.RequestLimits.MaxActionsPerResource,
		MaxResourcesPerRequest: serverConf.RequestLimits.MaxResourcesPerRequest,
	}

	return &CoreComponents{
		Engine:     eng,
		AuxData:    auxData,
		AuditLog:   auditLog,
		Store:      store,
		ReqLimits:  reqLimits,
		SuggestHub: auditLog.Backend() != audithub.Backend && store.Driver() != storagehub.DriverName,
	}, nil
}
