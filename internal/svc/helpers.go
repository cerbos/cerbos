// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

const (
	metaTagKey         = "meta"
	requestIDTagKey    = "request_id"
	playgroundIDTagKey = "playground_id"
)

func ExtractRequestFields(fullMethod string, req interface{}) map[string]interface{} {
	if req == nil {
		return nil
	}

	switch fullMethod {
	case "/cerbos.vc.v1.CerbosService/CheckResourceSet":
		crsReq, ok := req.(*requestv1.CheckResourceSetRequest)
		if !ok || crsReq.RequestId == "" {
			return nil
		}

		return map[string]interface{}{
			metaTagKey: map[string]string{requestIDTagKey: crsReq.RequestId},
		}

	case "/cerbos.svc.v1.CerbosService/CheckResourceBatch":
		crbReq, ok := req.(*requestv1.CheckResourceBatchRequest)
		if !ok || crbReq.RequestId == "" {
			return nil
		}

		return map[string]interface{}{
			metaTagKey: map[string]string{requestIDTagKey: crbReq.RequestId},
		}

	case "/cerbos.svc.v1.CerbosPlaygroundService/PlaygroundValidate":
		pgReq, ok := req.(*requestv1.PlaygroundValidateRequest)
		if !ok || pgReq.PlaygroundId == "" {
			return nil
		}

		return map[string]interface{}{
			metaTagKey: map[string]string{playgroundIDTagKey: pgReq.PlaygroundId},
		}

	case "/cerbos.svc.v1.CerbosPlaygroundService/PlaygroundEvaluate":
		pgReq, ok := req.(*requestv1.PlaygroundEvaluateRequest)
		if !ok || pgReq.PlaygroundId == "" {
			return nil
		}

		return map[string]interface{}{
			metaTagKey: map[string]string{playgroundIDTagKey: pgReq.PlaygroundId},
		}

	default:
		return nil
	}
}

func SetHTTPStatusCode(ctx context.Context, code int) {
	_ = grpc.SendHeader(ctx, metadata.Pairs("x-http-code", strconv.Itoa(code)))
}

func getStringValue(v interface{}) string {
	if s, ok := v.([]interface{}); ok && len(s) != 0 {
		return getStringValue(s[0])
	}

	return fmt.Sprint(v)
}

// protoMessageToStringMap returns map[string]interface{} representation of the proto message.
// jsonpath lib explicitly requires either map[string]interface{} or slice of interface{}.
func protoMessageToStringMap(m protoreflect.ProtoMessage) (map[string]interface{}, error) {
	b, err := protojson.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("could not marshal policy: %w", err)
	}

	var v map[string]interface{}
	err = json.Unmarshal(b, &v)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal policy: %w", err)
	}

	return v, nil
}
