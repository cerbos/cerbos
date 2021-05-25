// Copyright 2021 Zenauth Ltd.

package svc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/afero"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	enginev1 "github.com/cerbos/cerbos/internal/genpb/engine/v1"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/mem"
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

func (cs *CerbosPlaygroundService) Playground(ctx context.Context, req *requestv1.PlaygroundRequest) (*responsev1.PlaygroundResponse, error) {
	log := ctxzap.Extract(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	fs := afero.NewMemMapFs()
	for _, pf := range req.PolicyFiles {
		if err := afero.WriteFile(fs, pf.FileName, pf.Contents, 0644); err != nil {
			log.Error("Failed to create in-mem policy file", zap.String("policy_file", pf.FileName), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "failed to create policy file %s", pf.FileName)
		}
	}

	store, err := mem.NewStore(procCtx, fs)
	if err != nil {
		idxErr := new(disk.IndexBuildError)
		if errors.As(err, &idxErr) {
			return processLintErrors(ctx, req.PlaygroundId, idxErr)
		}

		log.Error("Failed to create mem store", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to create mem store")
	}

	eng, err := engine.NewEphemeral(procCtx, store)
	if err != nil {
		compErr := new(compile.ErrorList)
		if errors.As(err, compErr) {
			return processCompileErrors(ctx, req.PlaygroundId, *compErr)
		}

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

func processLintErrors(ctx context.Context, playgroundID string, errs *disk.IndexBuildError) (*responsev1.PlaygroundResponse, error) {
	var errors []*responsev1.PlaygroundResponse_Error //nolint:prealloc

	for _, dd := range errs.DuplicateDefs {
		errors = append(errors, &responsev1.PlaygroundResponse_Error{
			File:  dd.File,
			Error: fmt.Sprintf("%s is a duplicate of %s", dd.File, dd.OtherFile),
		})
	}

	for _, mi := range errs.MissingImports {
		errors = append(errors, &responsev1.PlaygroundResponse_Error{
			File:  mi.ImportingFile,
			Error: mi.Desc,
		})
	}

	for _, lf := range errs.LoadFailures {
		errors = append(errors, &responsev1.PlaygroundResponse_Error{
			File:  lf.File,
			Error: fmt.Sprintf("Failed to read: %s", lf.Err.Error()),
		})
	}

	for _, d := range errs.Disabled {
		errors = append(errors, &responsev1.PlaygroundResponse_Error{
			File:  d,
			Error: "Disabled policy",
		})
	}

	_ = grpc.SendHeader(ctx, metadata.Pairs("x-http-code", "400"))

	return &responsev1.PlaygroundResponse{
		PlaygroundId: playgroundID,
		Outcome: &responsev1.PlaygroundResponse_Failure{
			Failure: &responsev1.PlaygroundResponse_ErrorList{Errors: errors},
		},
	}, nil
}

func processCompileErrors(ctx context.Context, playgroundID string, errs compile.ErrorList) (*responsev1.PlaygroundResponse, error) {
	errors := make([]*responsev1.PlaygroundResponse_Error, len(errs))

	for i, err := range errs {
		errors[i] = &responsev1.PlaygroundResponse_Error{
			File:  err.File,
			Error: fmt.Sprintf("%s (%s)", err.Description, err.Err.Error()),
		}
	}

	_ = grpc.SendHeader(ctx, metadata.Pairs("x-http-code", "400"))

	return &responsev1.PlaygroundResponse{
		PlaygroundId: playgroundID,
		Outcome: &responsev1.PlaygroundResponse_Failure{
			Failure: &responsev1.PlaygroundResponse_ErrorList{Errors: errors},
		},
	}, nil
}

func processEngineOutput(_ context.Context, playgroundID string, outputs []*enginev1.CheckOutput) (*responsev1.PlaygroundResponse, error) {
	if len(outputs) != 1 {
		return nil, status.Errorf(codes.Internal, "Unexpected engine output")
	}

	results := make([]*responsev1.PlaygroundResponse_EvalResult, 0, len(outputs[0].Actions))

	for action, effect := range outputs[0].Actions {
		results = append(results, &responsev1.PlaygroundResponse_EvalResult{
			Action:                action,
			Effect:                effect.Effect,
			Policy:                effect.Policy,
			EffectiveDerivedRoles: outputs[0].EffectiveDerivedRoles,
		})
	}

	return &responsev1.PlaygroundResponse{
		PlaygroundId: playgroundID,
		Outcome: &responsev1.PlaygroundResponse_Success{
			Success: &responsev1.PlaygroundResponse_EvalResultList{Results: results},
		},
	}, nil
}
