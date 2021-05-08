// Copyright 2021 Zenauth Ltd.

package svc

import (
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	"github.com/cerbos/cerbos/internal/util"
)

func ExtractRequestFields(fullMethod string, req interface{}) map[string]interface{} {
	if req == nil {
		return nil
	}

	switch fullMethod {
	case "/svc.v1.CerbosService/CheckResourceBatch":
		batchReq, ok := req.(*requestv1.CheckResourceBatchRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]map[string]string{
				"request": {
					"id":                       batchReq.RequestId,
					"principal.id":             batchReq.Principal.Id,
					"principal.policy_version": batchReq.Principal.PolicyVersion,
				},
			},
		}
	default:
		return nil
	}
}
