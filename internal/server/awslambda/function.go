// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/svc"
)

// FunctionHandler handles AWS Lambda function invocations.
type FunctionHandler struct {
	svc  *svc.CerbosService
	core *server.CoreComponents
}

func NewFunctionHandler(ctx context.Context) (*FunctionHandler, error) {
	log := zap.L().Named("lambda-func")

	configPath := os.Getenv("CERBOS_CONFIG")

	log.Info("Loading configuration", zap.String("configPath", configPath))

	overrides := make(map[string]any)
	if configPath == "" {
		if err := MkConfStorageOverrides("/opt/policies", overrides); err != nil {
			return nil, fmt.Errorf("failed to create config overrides: %w", err)
		}
	}

	if err := config.Load(configPath, overrides); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	core, err := server.InitializeCerbosCore(ctx)
	if err != nil {
		return nil, err
	}

	cerbosSvc := svc.NewCerbosService(core.Engine, core.AuxData, core.ReqLimits)

	log.Info("Lambda function handler initialized successfully")
	return &FunctionHandler{
		svc:  cerbosSvc,
		core: core,
	}, nil
}

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

func (h *FunctionHandler) Close() error {
	log := zap.L().Named("lambda-func")

	log.Debug("Shutting down the audit log")
	if err := h.core.AuditLog.Close(); err != nil {
		log.Error("Failed to cleanly close audit log", zap.Error(err))
		return err
	}

	if closer, ok := h.core.Store.(io.Closer); ok {
		log.Debug("Shutting down store")
		if err := closer.Close(); err != nil {
			log.Error("Store didn't shutdown correctly", zap.Error(err))
			return err
		}
	}

	log.Debug("Lambda function handler shutdown complete")
	return nil
}
