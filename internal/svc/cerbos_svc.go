// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"errors"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/util"
)

var _ svcv1.CerbosServiceServer = (*CerbosService)(nil)

// CerbosService implements the policy checking service.
type CerbosService struct {
	eng     *engine.Engine
	auxData *auxdata.AuxData
	*svcv1.UnimplementedCerbosServiceServer
}

func NewCerbosService(eng *engine.Engine, auxData *auxdata.AuxData) *CerbosService {
	return &CerbosService{
		eng:                              eng,
		auxData:                          auxData,
		UnimplementedCerbosServiceServer: &svcv1.UnimplementedCerbosServiceServer{},
	}
}

func (cs *CerbosService) ResourcesQueryPlan(ctx context.Context, request *requestv1.ResourcesQueryPlanRequest) (*responsev1.ResourcesQueryPlanResponse, error) {
	log := ctxzap.Extract(ctx)

	auxData, err := cs.auxData.Extract(ctx, request.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "failed to extract auxData")
	}

	input := &enginev1.ResourcesQueryPlanRequest{
		RequestId:   request.RequestId,
		Action:      request.Action,
		Principal:   request.Principal,
		Resource:    request.Resource,
		AuxData:     auxData,
		IncludeMeta: request.IncludeMeta,
	}
	response, err := cs.eng.ResourcesQueryPlan(logging.ToContext(ctx, log), input)
	if err != nil {
		log.Error("Resources query plan request failed", zap.Error(err))
		var e *engine.NoSuchKeyError
		if errors.As(err, &e) {
			return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", e)
		}
		if errors.Is(err, engine.ErrNoPoliciesMatched) {
			return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "Resources query plan request failed")
	}

	return response, nil
}

func (cs *CerbosService) CheckResourceSet(ctx context.Context, req *requestv1.CheckResourceSetRequest) (*responsev1.CheckResourceSetResponse, error) {
	log := ctxzap.Extract(ctx)

	auxData, err := cs.auxData.Extract(ctx, req.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "failed to extract auxData")
	}

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
				Scope:         req.Resource.Scope,
				Id:            key,
				Attr:          res.Attr,
			},
			AuxData: auxData,
		}
		idxToKey[i] = key
		i++
	}

	outputs, err := cs.eng.Check(logging.ToContext(ctx, log), inputs)
	if err != nil {
		log.Error("Policy check failed", zap.Error(err))
		if errors.As(err, &compile.PolicyCompilationErr{}) {
			return nil, status.Errorf(codes.FailedPrecondition, "Check failed due to invalid policy")
		}
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

	auxData, err := cs.auxData.Extract(ctx, req.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "failed to extract auxData")
	}

	inputs := make([]*enginev1.CheckInput, len(req.Resources))
	for i, res := range req.Resources {
		inputs[i] = &enginev1.CheckInput{
			RequestId: req.RequestId,
			Actions:   res.Actions,
			Principal: req.Principal,
			Resource:  res.Resource,
			AuxData:   auxData,
		}
	}

	outputs, err := cs.eng.Check(logging.ToContext(ctx, log), inputs)
	if err != nil {
		log.Error("Policy check failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Policy check failed")
	}

	result := &responsev1.CheckResourceBatchResponse{
		RequestId: req.RequestId,
		Results:   make([]*responsev1.CheckResourceBatchResponse_ActionEffectMap, len(outputs)),
	}

	for i, out := range outputs {
		aem := make(map[string]effectv1.Effect, len(out.Actions))
		for action, actionEffect := range out.Actions {
			aem[action] = actionEffect.Effect
		}

		result.Results[i] = &responsev1.CheckResourceBatchResponse_ActionEffectMap{
			ResourceId:       inputs[i].Resource.Id,
			Actions:          aem,
			ValidationErrors: out.ValidationErrors,
		}
	}

	return result, nil
}

func (CerbosService) ServerInfo(ctx context.Context, req *requestv1.ServerInfoRequest) (*responsev1.ServerInfoResponse, error) {
	return &responsev1.ServerInfoResponse{
		Version:   util.Version,
		Commit:    util.Commit,
		BuildDate: util.BuildDate,
	}, nil
}
