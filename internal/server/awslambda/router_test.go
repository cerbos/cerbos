// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/observability/logging"
)

func TestRouteRequest(t *testing.T) {
	ctx := context.Background()
	logging.InitLogging(ctx, "ERROR")

	t.Run("health check", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			RawPath: "/",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
					Method: "GET",
				},
				RequestID: "test-request",
			},
		}

		resp, err := RouteRequest(ctx, event, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, resp.Body, `"status":"ok"`)
	})

	t.Run("method not allowed", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			RawPath: "/v1/check/resources",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
					Method: "GET",
				},
				RequestID: "test-request",
			},
		}

		resp, err := RouteRequest(ctx, event, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		require.Contains(t, resp.Body, "method GET not allowed")
	})

	t.Run("path not found", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			RawPath: "/unknown/path",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
					Method: "POST",
				},
				RequestID: "test-request",
			},
		}

		resp, err := RouteRequest(ctx, event, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		require.Contains(t, resp.Body, "path /unknown/path not found")
	})

	t.Run("invalid request body for check resources", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			RawPath: "/v1/check/resources",
			Body:    "",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
					Method: "POST",
				},
				RequestID: "test-request",
			},
		}

		resp, err := RouteRequest(ctx, event, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Contains(t, resp.Body, "request body is required")
	})
}

func TestHandleCheckResources(t *testing.T) {
	ctx := context.Background()
	logging.InitLogging(ctx, "ERROR")

	t.Run("invalid request body", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			RawPath: "/v1/check/resources",
			Body:    "",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
					Method: "POST",
				},
				RequestID: "test-request",
			},
		}

		resp, err := handleCheckResources(ctx, event, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("malformed JSON", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			RawPath: "/v1/check/resources",
			Body:    "invalid json",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
					Method: "POST",
				},
				RequestID: "test-request",
			},
		}

		resp, err := handleCheckResources(ctx, event, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestHandlePlanResources(t *testing.T) {
	ctx := context.Background()
	logging.InitLogging(ctx, "ERROR")

	t.Run("invalid request body", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			RawPath: "/v1/plan/resources",
			Body:    "",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
					Method: "POST",
				},
				RequestID: "test-request",
			},
		}

		resp, err := handlePlanResources(ctx, event, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}