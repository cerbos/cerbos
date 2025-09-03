// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/ruletable"
	internalSchema "github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/overlay"
	"github.com/cerbos/cerbos/internal/svc"
)

// FunctionHandler handles AWS Lambda function invocations.
type FunctionHandler struct {
	svc *svc.CerbosService
}

// NewFunctionHandler creates a new Lambda function handler.
func NewFunctionHandler(ctx context.Context) (*FunctionHandler, error) {
	log := zap.L().Named("lambda-func")

	configPath := os.Getenv("CERBOS_CONFIG")
	if configPath == "" {
		configPath = "/var/task/.cerbos.yaml"
	}

	log.Info("Loading configuration", zap.String("configPath", configPath))
	if err := config.Load(configPath, nil); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	auditLog, err := audit.NewLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log: %w", err)
	}

	mdExtractor, err := audit.NewMetadataExtractor()
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata extractor: %w", err)
	}

	store, err := storage.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	var policyLoader policyloader.PolicyLoader
	switch st := store.(type) {
	case overlay.Overlay:
		pl, err := st.GetOverlayPolicyLoader(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create overlay policy loader: %w", err)
		}
		policyLoader = pl
	case storage.BinaryStore:
		policyLoader = st
	case storage.SourceStore:
		policyLoader, err = compile.NewManager(ctx, st)
		if err != nil {
			return nil, fmt.Errorf("failed to create compile manager: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid store type")
	}

	rt := ruletable.NewProtoRuletable()
	if err := ruletable.LoadPolicies(ctx, rt, policyLoader); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	schemaMgr, err := internalSchema.New(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("failed to create schema manager: %w", err)
	}

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, policyLoader, store, schemaMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create ruletable manager: %w", err)
	}

	if ss, ok := policyLoader.(storage.Subscribable); ok {
		ss.Subscribe(ruletableMgr)
	}

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

	auxData, err := auxdata.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auxData handler: %w", err)
	}

	serverConf, err := server.GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to get server configuration: %w", err)
	}

	reqLimits := svc.RequestLimits{
		MaxActionsPerResource:  serverConf.RequestLimits.MaxActionsPerResource,
		MaxResourcesPerRequest: serverConf.RequestLimits.MaxResourcesPerRequest,
	}

	cerbosSvc := svc.NewCerbosService(eng, auxData, reqLimits)

	log.Info("Lambda function handler initialized successfully")
	return &FunctionHandler{
		svc: cerbosSvc,
	}, nil
}

// Handle processes AWS Lambda function invocations.
func (h *FunctionHandler) Handle(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	start := time.Now()

	// Add request ID and other metadata to logging context
	reqLog := logging.ReqScopeLog(ctx).With(
		zap.String("requestId", event.RequestContext.RequestID),
		// TODO: AWS X-Ray trace ID is available in context or headers, not directly in event
		zap.String("path", event.RawPath),
		zap.String("method", event.RequestContext.HTTP.Method),
		zap.String("sourceIp", event.RequestContext.HTTP.SourceIP),
		zap.String("userAgent", event.RequestContext.HTTP.UserAgent),
	)
	ctx = logging.ToContext(ctx, reqLog)

	reqLog.Info("Processing Lambda request")

	resp, err := RouteRequest(ctx, event, h.svc)

	duration := time.Since(start)
	reqLog.Info("Lambda request completed",
		zap.Duration("duration", duration),
		zap.Int("statusCode", resp.StatusCode),
		zap.Error(err),
	)

	return resp, err
}
