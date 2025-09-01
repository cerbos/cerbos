// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/svc"
)

// RouteRequest routes the API Gateway request to the appropriate handler
func RouteRequest(ctx context.Context, event events.APIGatewayV2HTTPRequest, svc *svc.CerbosService) (events.APIGatewayV2HTTPResponse, error) {
	log := logging.ReqScopeLog(ctx)

	// Health check endpoint
	if event.RawPath == "/" && event.RequestContext.HTTP.Method == "GET" {
		return handleHealthCheck()
	}

	// Ensure POST method for API endpoints
	if event.RequestContext.HTTP.Method != "POST" {
		log.Warn("Method not allowed", zap.String("method", event.RequestContext.HTTP.Method))
		return ErrorToAPIGateway(fmt.Errorf("method %s not allowed", event.RequestContext.HTTP.Method), http.StatusMethodNotAllowed), nil
	}

	// Route based on path
	switch {
	case strings.HasSuffix(event.RawPath, "/v1/check/resources"):
		return handleCheckResources(ctx, event, svc)
	case strings.HasSuffix(event.RawPath, "/v1/plan/resources"):
		return handlePlanResources(ctx, event, svc)
	default:
		log.Warn("Path not found", zap.String("path", event.RawPath))
		return ErrorToAPIGateway(fmt.Errorf("path %s not found", event.RawPath), http.StatusNotFound), nil
	}
}

func handleHealthCheck() (events.APIGatewayV2HTTPResponse, error) {
	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body:            `{"status":"ok"}`,
		IsBase64Encoded: false,
	}, nil
}

func handleCheckResources(ctx context.Context, event events.APIGatewayV2HTTPRequest, svc *svc.CerbosService) (events.APIGatewayV2HTTPResponse, error) {
	log := logging.ReqScopeLog(ctx)
	
	// Convert API Gateway event to CheckResourcesRequest
	req, err := APIGatewayEventToCheckResourcesRequest(event)
	if err != nil {
		log.Error("Failed to convert request", zap.Error(err))
		return ErrorToAPIGateway(err, http.StatusBadRequest), nil
	}

	// Call the service
	resp, err := svc.CheckResources(ctx, req)
	if err != nil {
		log.Error("CheckResources failed", zap.Error(err))
		return ErrorToAPIGateway(err, http.StatusInternalServerError), nil
	}

	// Convert response to API Gateway format
	return CheckResourcesResponseToAPIGateway(resp)
}

func handlePlanResources(ctx context.Context, event events.APIGatewayV2HTTPRequest, svc *svc.CerbosService) (events.APIGatewayV2HTTPResponse, error) {
	log := logging.ReqScopeLog(ctx)
	
	// Convert API Gateway event to PlanResourcesRequest
	req, err := APIGatewayEventToPlanResourcesRequest(event)
	if err != nil {
		log.Error("Failed to convert request", zap.Error(err))
		return ErrorToAPIGateway(err, http.StatusBadRequest), nil
	}

	// Call the service
	resp, err := svc.PlanResources(ctx, req)
	if err != nil {
		log.Error("PlanResources failed", zap.Error(err))
		return ErrorToAPIGateway(err, http.StatusInternalServerError), nil
	}

	// Convert response to API Gateway format
	return PlanResourcesResponseToAPIGateway(resp)
}