// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"errors"
	"maps"
	"slices"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/planner"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/util"
)

var _ svcv1.CerbosServiceServer = (*CerbosService)(nil)

// CerbosService implements the policy checking service.
type CerbosService struct {
	eng     *engine.Engine
	auxData *auxdata.AuxData
	*svcv1.UnimplementedCerbosServiceServer
	reqLimits RequestLimits
}

type RequestLimits struct {
	MaxActionsPerResource  uint
	MaxResourcesPerRequest uint
}

func NewCerbosService(eng *engine.Engine, auxData *auxdata.AuxData, reqLimits RequestLimits) *CerbosService {
	return &CerbosService{
		eng:                              eng,
		auxData:                          auxData,
		reqLimits:                        reqLimits,
		UnimplementedCerbosServiceServer: &svcv1.UnimplementedCerbosServiceServer{},
	}
}

func (cs *CerbosService) PlanResources(ctx context.Context, request *requestv1.PlanResourcesRequest) (*responsev1.PlanResourcesResponse, error) {
	log := logging.ReqScopeLog(ctx)

	auxData, err := cs.auxData.Extract(ctx, request.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "invalid auxData")
	}

	oneAction := false
	if request.Action != "" {
		request.Actions = []string{request.Action}
		oneAction = true
	}

	outputs := make([]*enginev1.PlanResourcesOutput, 0, len(request.Actions))
	matchedScopes := make(map[string]string, len(request.Actions))
	for _, action := range request.Actions {
		input := &enginev1.PlanResourcesInput{
			RequestId:   request.RequestId,
			Action:      action,
			Principal:   request.Principal,
			Resource:    request.Resource,
			AuxData:     auxData,
			IncludeMeta: true,
		}
		output, err := cs.eng.PlanResources(logging.ToContext(ctx, log), input)
		if err != nil {
			log.Error("Resources query plan request failed", zap.Error(err))
			if errors.Is(err, compile.PolicyCompilationErr{}) {
				return nil, status.Errorf(codes.FailedPrecondition, "Resources query plan failed due to invalid policy")
			}
			return nil, status.Errorf(codes.Internal, "Resources query plan request failed")
		}
		outputs = append(outputs, output)
		matchedScopes[action] = output.Scope
	}

	validationErrors := make([]*schemav1.ValidationError, 0, len(outputs))
	for _, output := range outputs {
		validationErrors = append(validationErrors, output.ValidationErrors...)
	}
	if len(validationErrors) > 0 {
		m := make(map[string]*schemav1.ValidationError, len(validationErrors))
		for _, e := range validationErrors {
			m[e.String()] = e
		}
		validationErrors = slices.Collect(maps.Values(m))
	}

	filter, filterDebug := outputs[0].Filter, outputs[0].FilterDebug
	if len(outputs) > 1 {
		filter, filterDebug, err = planner.MergeWithAnd(outputs)
		if err != nil {
			log.Error("Resources query plan request failed", zap.Error(err))
			return nil, status.Errorf(codes.Internal, "Merging plans failed")
		}
	}
	response := &responsev1.PlanResourcesResponse{
		RequestId:        request.RequestId,
		Actions:          request.Actions,
		ResourceKind:     request.Resource.Kind,
		PolicyVersion:    request.Resource.PolicyVersion,
		Filter:           filter,
		ValidationErrors: validationErrors,
	}

	if request.IncludeMeta {
		response.Meta = &responsev1.PlanResourcesResponse_Meta{
			FilterDebug:   filterDebug,
			MatchedScopes: matchedScopes,
		}
	}

	if oneAction {
		response.Action = request.Action
		response.Actions = nil
		if request.IncludeMeta {
			response.Meta.MatchedScope = matchedScopes[response.Action]
			response.Meta.MatchedScopes = nil
		}
	}

	return response, nil
}

// CheckResourceSet checks a batch of homogenous resources.
// Deprecated: Since 0.16.0. Use CheckResources instead.
func (cs *CerbosService) CheckResourceSet(ctx context.Context, req *requestv1.CheckResourceSetRequest) (*responsev1.CheckResourceSetResponse, error) {
	log := logging.ReqScopeLog(ctx)
	if err := cs.checkNumResourcesLimit(len(req.Resource.Instances)); err != nil {
		log.Error("Request too large", zap.Error(err))
		return nil, err
	}

	if err := cs.checkNumActionsLimit(len(req.Actions)); err != nil {
		log.Error("Request too large", zap.Error(err))
		return nil, err
	}

	auxData, err := cs.auxData.Extract(ctx, req.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "invalid auxData")
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
		if errors.Is(err, compile.PolicyCompilationErr{}) {
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

// CheckResourceBatch checks a batch of heterogenous resources.
// Deprecated: Since 0.16.0. Use CheckResources instead.
func (cs *CerbosService) CheckResourceBatch(ctx context.Context, req *requestv1.CheckResourceBatchRequest) (*responsev1.CheckResourceBatchResponse, error) {
	log := logging.ReqScopeLog(ctx)
	if err := cs.checkNumResourcesLimit(len(req.Resources)); err != nil {
		log.Error("Request too large", zap.Error(err))
		return nil, err
	}

	auxData, err := cs.auxData.Extract(ctx, req.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "invalid auxData")
	}

	inputs := make([]*enginev1.CheckInput, len(req.Resources))
	for i, res := range req.Resources {
		if err := cs.checkNumActionsLimit(len(res.Actions)); err != nil {
			log.Error("Request too large", zap.Error(err))
			return nil, err
		}

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
		if errors.Is(err, compile.PolicyCompilationErr{}) {
			return nil, status.Errorf(codes.FailedPrecondition, "Check failed due to invalid policy")
		}
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

// CheckResources checks a batch of heterogenous resources.
func (cs *CerbosService) CheckResources(ctx context.Context, req *requestv1.CheckResourcesRequest) (*responsev1.CheckResourcesResponse, error) {
	log := logging.ReqScopeLog(ctx)
	if err := cs.checkNumResourcesLimit(len(req.Resources)); err != nil {
		log.Error("Request too large", zap.Error(err))
		return nil, err
	}

	auxData, err := cs.auxData.Extract(ctx, req.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "invalid auxData")
	}

	inputs := make([]*enginev1.CheckInput, len(req.Resources))
	for i, res := range req.Resources {
		if err := cs.checkNumActionsLimit(len(res.Actions)); err != nil {
			log.Error("Request too large", zap.Error(err))
			return nil, err
		}

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
		if errors.Is(err, compile.PolicyCompilationErr{}) {
			return nil, status.Errorf(codes.FailedPrecondition, "Check failed due to invalid policy")
		}
		return nil, status.Errorf(codes.Internal, "Policy check failed")
	}

	return tracing.RecordSpan2(ctx, "assemble_response", func(_ context.Context, _ trace.Span) (*responsev1.CheckResourcesResponse, error) {
		result := &responsev1.CheckResourcesResponse{
			RequestId: req.RequestId,
			Results:   make([]*responsev1.CheckResourcesResponse_ResultEntry, len(outputs)),
		}

		for i, out := range outputs {
			resource := inputs[i].Resource
			entry := &responsev1.CheckResourcesResponse_ResultEntry{
				Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
					Id:            resource.Id,
					Kind:          resource.Kind,
					PolicyVersion: resource.PolicyVersion,
					Scope:         resource.Scope,
				},
				ValidationErrors: out.ValidationErrors,
				Actions:          make(map[string]effectv1.Effect, len(out.Actions)),
			}

			if req.IncludeMeta {
				entry.Meta = &responsev1.CheckResourcesResponse_ResultEntry_Meta{
					EffectiveDerivedRoles: out.EffectiveDerivedRoles,
					Actions:               make(map[string]*responsev1.CheckResourcesResponse_ResultEntry_Meta_EffectMeta, len(out.Actions)),
				}
			}

			if len(out.Outputs) > 0 {
				entry.Outputs = out.Outputs
			}

			for action, actionEffect := range out.Actions {
				entry.Actions[action] = actionEffect.Effect
				if req.IncludeMeta {
					entry.Meta.Actions[action] = &responsev1.CheckResourcesResponse_ResultEntry_Meta_EffectMeta{
						MatchedPolicy: actionEffect.Policy,
						MatchedScope:  actionEffect.Scope,
					}
				}
			}

			result.Results[i] = entry
		}

		return result, nil
	})
}

func (cs *CerbosService) checkNumResourcesLimit(n int) error {
	if n > int(cs.reqLimits.MaxResourcesPerRequest) {
		return status.Errorf(codes.InvalidArgument,
			"number of resources in batch (%d) exceeds configured limit (%d)", n, cs.reqLimits.MaxResourcesPerRequest)
	}

	return nil
}

func (cs *CerbosService) checkNumActionsLimit(n int) error {
	if n > int(cs.reqLimits.MaxActionsPerResource) {
		return status.Errorf(codes.InvalidArgument,
			"number of actions (%d) exceeds configured limit (%d)", n, cs.reqLimits.MaxActionsPerResource)
	}

	return nil
}

func (CerbosService) ServerInfo(_ context.Context, _ *requestv1.ServerInfoRequest) (*responsev1.ServerInfoResponse, error) {
	return &responsev1.ServerInfoResponse{
		Version:   util.Version,
		Commit:    util.Commit,
		BuildDate: util.BuildDate,
	}, nil
}
