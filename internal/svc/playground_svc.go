// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/afero"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
)

const playgroundRequestTimeout = 60 * time.Second

var _ svcv1.CerbosPlaygroundServiceServer = (*CerbosPlaygroundService)(nil)

// CerbosPlaygroundService implements the playground API.
type CerbosPlaygroundService struct {
	*svcv1.UnimplementedCerbosPlaygroundServiceServer
}

func NewCerbosPlaygroundService() *CerbosPlaygroundService {
	return &CerbosPlaygroundService{
		UnimplementedCerbosPlaygroundServiceServer: &svcv1.UnimplementedCerbosPlaygroundServiceServer{},
	}
}

func (cs *CerbosPlaygroundService) PlaygroundValidate(ctx context.Context, req *requestv1.PlaygroundValidateRequest) (*responsev1.PlaygroundValidateResponse, error) {
	log := ctxzap.Extract(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	_, fail, err := doCompile(procCtx, log, req.PolicyFiles)
	if err != nil {
		return nil, err
	}

	if fail != nil {
		return &responsev1.PlaygroundValidateResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundValidateResponse_Failure{
				Failure: fail,
			},
		}, nil
	}

	return &responsev1.PlaygroundValidateResponse{
		PlaygroundId: req.PlaygroundId,
		Outcome: &responsev1.PlaygroundValidateResponse_Success{
			Success: &emptypb.Empty{},
		},
	}, nil
}

func (cs *CerbosPlaygroundService) PlaygroundEvaluate(ctx context.Context, req *requestv1.PlaygroundEvaluateRequest) (*responsev1.PlaygroundEvaluateResponse, error) {
	log := ctxzap.Extract(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	idx, fail, err := doCompile(procCtx, log, req.PolicyFiles)
	if err != nil {
		return nil, err
	}

	if fail != nil {
		return &responsev1.PlaygroundEvaluateResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundEvaluateResponse_Failure{
				Failure: fail,
			},
		}, nil
	}

	eng, err := engine.NewEphemeral(ctx, compile.NewManager(ctx, disk.NewFromIndex(idx)))
	if err != nil {
		log.Error("Failed to create engine", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to create engine")
	}

	inputs := []*enginev1.CheckInput{
		{
			RequestId: req.PlaygroundId,
			Actions:   req.Actions,
			Principal: req.Principal,
			Resource:  req.Resource,
		},
	}

	output, err := eng.Check(procCtx, inputs)
	if err != nil {
		log.Error("Engine check failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "policy check failed")
	}

	return processEngineOutput(ctx, req.PlaygroundId, output)
}

func (cs *CerbosPlaygroundService) PlaygroundProxy(ctx context.Context, req *requestv1.PlaygroundProxyRequest) (*responsev1.PlaygroundProxyResponse, error) {
	log := ctxzap.Extract(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	idx, fail, err := doCompile(procCtx, log, req.PolicyFiles)
	if err != nil {
		return nil, err
	}

	if fail != nil {
		return &responsev1.PlaygroundProxyResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundProxyResponse_Failure{
				Failure: fail,
			},
		}, nil
	}

	eng, err := engine.NewEphemeral(ctx, compile.NewManager(ctx, disk.NewFromIndex(idx)))
	if err != nil {
		log.Error("Failed to create engine", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to create engine")
	}

	cerbosSvc := NewCerbosService(eng)
	switch proxyReq := req.ProxyRequest.(type) {
	case *requestv1.PlaygroundProxyRequest_CheckResourceSet:
		resp, err := cerbosSvc.CheckResourceSet(ctx, proxyReq.CheckResourceSet)
		if err != nil {
			return nil, err
		}

		return &responsev1.PlaygroundProxyResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundProxyResponse_CheckResourceSet{
				CheckResourceSet: resp,
			},
		}, nil
	case *requestv1.PlaygroundProxyRequest_CheckResourceBatch:
		resp, err := cerbosSvc.CheckResourceBatch(ctx, proxyReq.CheckResourceBatch)
		if err != nil {
			return nil, err
		}

		return &responsev1.PlaygroundProxyResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundProxyResponse_CheckResourceBatch{
				CheckResourceBatch: resp,
			},
		}, nil
	default:
		log.Error(fmt.Sprintf("Unhandled playground proxy request type %T", proxyReq))
		return nil, status.Error(codes.Unimplemented, "unknown request type")
	}
}

func doCompile(ctx context.Context, log *zap.Logger, files []*requestv1.PolicyFile) (index.Index, *responsev1.PlaygroundFailure, error) {
	idx, err := buildIndex(ctx, log, files)
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			pf := processLintErrors(ctx, idxErr)
			return nil, pf, nil
		}

		log.Error("Failed to create index", zap.Error(err))
		return nil, nil, status.Errorf(codes.Internal, "failed to create index")
	}

	if err := compile.BatchCompile(idx.GetAllCompilationUnits(ctx)); err != nil {
		compErr := new(compile.ErrorList)
		if errors.As(err, compErr) {
			pf := processCompileErrors(ctx, *compErr)
			return nil, pf, nil
		}

		log.Error("Failed to compile", zap.Error(err))
		return nil, nil, status.Errorf(codes.Internal, "failed to compile")
	}

	return idx, nil, nil
}

func buildIndex(ctx context.Context, log *zap.Logger, files []*requestv1.PolicyFile) (index.Index, error) {
	fs := afero.NewMemMapFs()
	for _, pf := range files {
		if err := afero.WriteFile(fs, pf.FileName, pf.Contents, 0o644); err != nil { //nolint:gomnd
			log.Error("Failed to create in-mem policy file", zap.String("policy_file", pf.FileName), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "failed to create policy file %s", pf.FileName)
		}
	}

	return index.Build(ctx, afero.NewIOFS(fs), index.WithMemoryCache())
}

func processLintErrors(ctx context.Context, errs *index.BuildError) *responsev1.PlaygroundFailure {
	var errors []*responsev1.PlaygroundFailure_Error //nolint:prealloc

	for _, dd := range errs.DuplicateDefs {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  dd.File,
			Error: fmt.Sprintf("%s is a duplicate of %s", dd.File, dd.OtherFile),
		})
	}

	for _, mi := range errs.MissingImports {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  mi.ImportingFile,
			Error: mi.Desc,
		})
	}

	for _, lf := range errs.LoadFailures {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  lf.File,
			Error: fmt.Sprintf("Failed to read: %s", lf.Err.Error()),
		})
	}

	for _, cf := range errs.CodegenFailures {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  cf.File,
			Error: fmt.Sprintf("Failed to generate code: %s", cf.Err.Error()),
		})
	}

	for _, d := range errs.Disabled {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  d,
			Error: "Disabled policy",
		})
	}

	SetHTTPStatusCode(ctx, http.StatusBadRequest)

	return &responsev1.PlaygroundFailure{Errors: errors}
}

func processCompileErrors(ctx context.Context, errs compile.ErrorList) *responsev1.PlaygroundFailure {
	errors := make([]*responsev1.PlaygroundFailure_Error, len(errs))

	for i, err := range errs {
		errors[i] = &responsev1.PlaygroundFailure_Error{
			File:  err.File,
			Error: fmt.Sprintf("%s (%s)", err.Description, err.Err.Error()),
		}
	}

	SetHTTPStatusCode(ctx, http.StatusBadRequest)

	return &responsev1.PlaygroundFailure{Errors: errors}
}

func processEngineOutput(_ context.Context, playgroundID string, outputs []*enginev1.CheckOutput) (*responsev1.PlaygroundEvaluateResponse, error) {
	if len(outputs) != 1 {
		return nil, status.Errorf(codes.Internal, "Unexpected engine output")
	}

	results := make([]*responsev1.PlaygroundEvaluateResponse_EvalResult, 0, len(outputs[0].Actions))

	for action, effect := range outputs[0].Actions {
		results = append(results, &responsev1.PlaygroundEvaluateResponse_EvalResult{
			Action:                action,
			Effect:                effect.Effect,
			Policy:                effect.Policy,
			EffectiveDerivedRoles: outputs[0].EffectiveDerivedRoles,
		})
	}

	return &responsev1.PlaygroundEvaluateResponse{
		PlaygroundId: playgroundID,
		Outcome: &responsev1.PlaygroundEvaluateResponse_Success{
			Success: &responsev1.PlaygroundEvaluateResponse_EvalResultList{Results: results},
		},
	}, nil
}
