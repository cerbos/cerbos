package svc

import (
	requestv1 "github.com/cerbos/cerbos/pkg/generated/request/v1"
	"github.com/cerbos/cerbos/pkg/util"
)

func ExtractRequestFields(fullMethod string, req interface{}) map[string]interface{} {
	switch fullMethod {
	case "/svc.v1.CerbosService/Check":
		checkReq, ok := req.(*requestv1.CheckRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]string{
				"request.id":                checkReq.RequestId,
				"request.principal.id":      checkReq.Principal.Id,
				"request.principal.version": checkReq.Principal.Version,
				"request.resource.name":     checkReq.Resource.Name,
				"request.resource.version":  checkReq.Resource.Version,
			},
		}
	default:
		return nil
	}
}
