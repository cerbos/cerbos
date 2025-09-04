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

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/server"
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

	core, err := server.InitializeCerbosCore(ctx)
	if err != nil {
		return nil, err
	}

	cerbosSvc := svc.NewCerbosService(core.Engine, core.AuxData, core.ReqLimits)

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
