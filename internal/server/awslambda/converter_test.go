// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

func TestAPIGatewayEventToCheckResourcesRequest(t *testing.T) {
	req := &requestv1.CheckResourcesRequest{
		RequestId: "test-request",
		Principal: &enginev1.Principal{
			Id:    "alice",
			Roles: []string{"user"},
		},
		Resources: []*requestv1.CheckResourcesRequest_ResourceEntry{
			{
				Resource: &enginev1.Resource{
					Kind: "document",
					Id:   "doc1",
				},
				Actions: []string{"read"},
			},
		},
	}

	jsonData, err := protojson.Marshal(req)
	require.NoError(t, err)

	t.Run("valid request", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			Body: string(jsonData),
		}

		result, err := APIGatewayEventToCheckResourcesRequest(event)
		require.NoError(t, err)
		require.Equal(t, req.RequestId, result.RequestId)
		require.Equal(t, req.Principal.Id, result.Principal.Id)
		require.Len(t, result.Resources, 1)
	})

	t.Run("base64 encoded request", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			Body:            base64.StdEncoding.EncodeToString(jsonData),
			IsBase64Encoded: true,
		}

		result, err := APIGatewayEventToCheckResourcesRequest(event)
		require.NoError(t, err)
		require.Equal(t, req.RequestId, result.RequestId)
	})

	t.Run("empty body", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			Body: "",
		}

		_, err := APIGatewayEventToCheckResourcesRequest(event)
		require.Error(t, err)
		require.Contains(t, err.Error(), "request body is required")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			Body: "invalid json",
		}

		_, err := APIGatewayEventToCheckResourcesRequest(event)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal")
	})

	t.Run("invalid base64", func(t *testing.T) {
		event := events.APIGatewayV2HTTPRequest{
			Body:            "invalid base64!",
			IsBase64Encoded: true,
		}

		_, err := APIGatewayEventToCheckResourcesRequest(event)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode base64")
	})
}

func TestCheckResourcesResponseToAPIGateway(t *testing.T) {
	resp := &responsev1.CheckResourcesResponse{
		RequestId: "test-request",
		Results: []*responsev1.CheckResourcesResponse_ResultEntry{
			{
				Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
					Id:   "doc1",
					Kind: "document",
				},
				Actions: map[string]effectv1.Effect{
					"read": effectv1.Effect_EFFECT_ALLOW,
				},
			},
		},
	}

	result, err := CheckResourcesResponseToAPIGateway(resp)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, result.StatusCode)
	require.Equal(t, "application/json", result.Headers["content-type"])
	require.False(t, result.IsBase64Encoded)

	// Verify the response can be unmarshaled back
	var unmarshaled responsev1.CheckResourcesResponse
	err = protojson.Unmarshal([]byte(result.Body), &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, resp.RequestId, unmarshaled.RequestId)
}

func TestErrorToAPIGateway(t *testing.T) {
	t.Run("generic error", func(t *testing.T) {
		err := errors.New("something went wrong")
		resp := ErrorToAPIGateway(err, http.StatusInternalServerError)

		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		require.Equal(t, "application/json", resp.Headers["content-type"])
		require.Contains(t, resp.Body, "something went wrong")

		var errorResp map[string]interface{}
		json.Unmarshal([]byte(resp.Body), &errorResp)
		require.Contains(t, errorResp, "error")
	})
}
