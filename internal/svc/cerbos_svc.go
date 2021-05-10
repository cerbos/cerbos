// Copyright 2021 Zenauth Ltd.

package svc

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cerbos/cerbos/internal/engine"
	enginev1 "github.com/cerbos/cerbos/internal/genpb/engine/v1"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
)

var _ svcv1.CerbosServiceServer = (*CerbosService)(nil)

// CerbosService implements the policy checking service.
type CerbosService struct {
	log *zap.SugaredLogger
	eng *engine.Engine
	*svcv1.UnimplementedCerbosServiceServer
}

func NewCerbosService(eng *engine.Engine) *CerbosService {
	return &CerbosService{
		log:                              zap.S().Named("check.svc"),
		eng:                              eng,
		UnimplementedCerbosServiceServer: &svcv1.UnimplementedCerbosServiceServer{},
	}
}

func (cs *CerbosService) CheckResourceSet(ctx context.Context, req *requestv1.CheckResourceSetRequest) (*responsev1.CheckResourceSetResponse, error) {
	log := ctxzap.Extract(ctx)

	inputs := make([]*enginev1.CheckInput, len(req.Resource.Instances))
	idxToKey := make([]string, len(req.Resource.Instances))

	i := 0
	for key, res := range req.Resource.Instances {
		inputs[i] = &enginev1.CheckInput{
			RequestId: req.RequestId,
			Actions:   req.Actions,
			Principal: req.Principal,
			Resource: &enginev1.Resource{
				Kind:          req.Resource.Kind,
				PolicyVersion: req.Resource.PolicyVersion,
				Id:            key,
				Attr:          res.Attr,
			},
		}
		idxToKey[i] = key
		i++
	}

	outputs, err := cs.eng.Check(logging.ToContext(ctx, log), inputs)
	if err != nil {
		log.Error("Policy check failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Policy check failed")
	}

	result := newCheckResourceSetResponseBuilder(req)
	for j, out := range outputs {
		result.addResult(idxToKey[j], out)
	}

	return result.build(), nil
}

func (cs *CerbosService) CheckResourceBatch(ctx context.Context, req *requestv1.CheckResourceBatchRequest) (*responsev1.CheckResourceBatchResponse, error) {
	log := ctxzap.Extract(ctx)

	inputs := make([]*enginev1.CheckInput, len(req.Resources))
	for i, res := range req.Resources {
		inputs[i] = &enginev1.CheckInput{
			RequestId: req.RequestId,
			Actions:   res.Actions,
			Principal: req.Principal,
			Resource:  res.Resource,
		}
	}

	outputs, err := cs.eng.Check(logging.ToContext(ctx, log), inputs)
	if err != nil {
		log.Error("Policy check failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Policy check failed")
	}

	result := &responsev1.CheckResourceBatchResponse{
		RequestId: req.RequestId,
		Results:   make([]*responsev1.ActionEffectMap, len(outputs)),
	}

	for i, out := range outputs {
		aem := make(map[string]sharedv1.Effect, len(out.Actions))
		for action, actionEffect := range out.Actions {
			aem[action] = actionEffect.Effect
		}

		result.Results[i] = &responsev1.ActionEffectMap{Actions: aem}
	}

	return result, nil
}
