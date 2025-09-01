// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/compile"
)

// parseRequestBody handles the common body parsing logic
func parseRequestBody(event events.APIGatewayV2HTTPRequest) ([]byte, error) {
	if event.Body == "" {
		return nil, fmt.Errorf("request body is required")
	}

	body := event.Body
	if event.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 body: %w", err)
		}
		body = string(decoded)
	}

	return []byte(body), nil
}

// APIGatewayEventToCheckResourcesRequest converts an API Gateway event to a CheckResourcesRequest
func APIGatewayEventToCheckResourcesRequest(event events.APIGatewayV2HTTPRequest) (*requestv1.CheckResourcesRequest, error) {
	body, err := parseRequestBody(event)
	if err != nil {
		return nil, err
	}

	var req requestv1.CheckResourcesRequest
	if err := protojson.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CheckResourcesRequest: %w", err)
	}

	return &req, nil
}

// APIGatewayEventToPlanResourcesRequest converts an API Gateway event to a PlanResourcesRequest
func APIGatewayEventToPlanResourcesRequest(event events.APIGatewayV2HTTPRequest) (*requestv1.PlanResourcesRequest, error) {
	body, err := parseRequestBody(event)
	if err != nil {
		return nil, err
	}

	var req requestv1.PlanResourcesRequest
	if err := protojson.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PlanResourcesRequest: %w", err)
	}

	return &req, nil
}

// ResponseToAPIGateway converts a protobuf response to an API Gateway response
func ResponseToAPIGateway[T proto.Message](resp T) (events.APIGatewayV2HTTPResponse, error) {
	jsonResp, err := protojson.Marshal(resp)
	if err != nil {
		typeName := resp.ProtoReflect().Descriptor().Name()
		return events.APIGatewayV2HTTPResponse{}, fmt.Errorf("failed to marshal %s: %w", typeName, err)
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body: string(jsonResp),
	}, nil
}

func CheckResourcesResponseToAPIGateway(resp *responsev1.CheckResourcesResponse) (events.APIGatewayV2HTTPResponse, error) {
	return ResponseToAPIGateway(resp)
}

func PlanResourcesResponseToAPIGateway(resp *responsev1.PlanResourcesResponse) (events.APIGatewayV2HTTPResponse, error) {
	return ResponseToAPIGateway(resp)
}

func ErrorToAPIGateway(message string, statusCode int) events.APIGatewayV2HTTPResponse {
	errorResp := map[string]any{
		"error": map[string]any{
			"message": message,
			"code":    statusCode,
		},
	}

	jsonResp, _ := json.Marshal(errorResp)

	return events.APIGatewayV2HTTPResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body: string(jsonResp),
	}
}
