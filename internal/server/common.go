// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/ruletable"
	internalSchema "github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/overlay"
	"github.com/cerbos/cerbos/internal/svc"
)

// CoreComponents holds the shared components needed for both server and Lambda function initialization.
type CoreComponents struct {
	Engine    *engine.Engine
	AuxData   *auxdata.AuxData
	AuditLog  audit.Log
	Store     storage.Store
	ReqLimits svc.RequestLimits
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
	case storage.SourceStore:
		// create compile manager
		policyLoader, err = compile.NewManager(ctx, st)
		if err != nil {
			return nil, fmt.Errorf("failed to create compile manager: %w", err)
		}
	default:
		return nil, ErrInvalidStore
	}

	rt := ruletable.NewProtoRuletable()

	if err := ruletable.LoadPolicies(ctx, rt, policyLoader); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// create schema manager
	schemaMgr, err := internalSchema.New(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("failed to create schema manager: %w", err)
	}

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, policyLoader, store, schemaMgr)
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
		Engine:    eng,
		AuxData:   auxData,
		AuditLog:  auditLog,
		Store:     store,
		ReqLimits: reqLimits,
	}, nil
}
