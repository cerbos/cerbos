// Copyright 2021 Zenauth Ltd.

package svc

import (
	"context"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	"github.com/cerbos/cerbos/internal/util"
)

func ExtractRequestFields(fullMethod string, req interface{}) map[string]interface{} {
	if req == nil {
		return nil
	}

	switch fullMethod {
	case "/svc.v1.CerbosService/CheckResourceSet":
		crsReq, ok := req.(*requestv1.CheckResourceSetRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]string{
				"request.id":               crsReq.RequestId,
				"principal.id":             crsReq.Principal.Id,
				"principal.policy_version": crsReq.Principal.PolicyVersion,
			},
		}

	case "/svc.v1.CerbosService/CheckResourceBatch":
		crbReq, ok := req.(*requestv1.CheckResourceBatchRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]string{
				"request.id":               crbReq.RequestId,
				"principal.id":             crbReq.Principal.Id,
				"principal.policy_version": crbReq.Principal.PolicyVersion,
			},
		}

	case "/svc.v1.CerbosPlaygroundService/PlaygroundValidate":
		pgReq, ok := req.(*requestv1.PlaygroundValidateRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]string{
				"playground.id": pgReq.PlaygroundId,
			},
		}

	case "/svc.v1.CerbosPlaygroundService/PlaygroundEvaluate":
		pgReq, ok := req.(*requestv1.PlaygroundEvaluateRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]string{
				"playground.id": pgReq.PlaygroundId,
			},
		}

	default:
		return nil
	}
}

func SetHTTPStatusCode(ctx context.Context, code int) {
	_ = grpc.SendHeader(ctx, metadata.Pairs("x-http-code", strconv.Itoa(code)))
}
