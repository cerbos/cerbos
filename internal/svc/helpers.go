// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

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
