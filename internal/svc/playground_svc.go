// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/afero"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/verify"
)

const playgroundRequestTimeout = 60 * time.Second

var _ svcv1.CerbosPlaygroundServiceServer = (*CerbosPlaygroundService)(nil)

// CerbosPlaygroundService implements the playground API.
type CerbosPlaygroundService struct {
	*svcv1.UnimplementedCerbosPlaygroundServiceServer
	auxData   *auxdata.AuxData
	reqLimits RequestLimits
}

func NewCerbosPlaygroundService(reqLimits RequestLimits) *CerbosPlaygroundService {
	return &CerbosPlaygroundService{
		UnimplementedCerbosPlaygroundServiceServer: &svcv1.UnimplementedCerbosPlaygroundServiceServer{},
		auxData:   auxdata.NewWithoutVerification(context.Background()),
		reqLimits: reqLimits,
	}
}

func (cs *CerbosPlaygroundService) PlaygroundValidate(ctx context.Context, req *requestv1.PlaygroundValidateRequest) (*responsev1.PlaygroundValidateResponse, error) {
	log := logging.ReqScopeLog(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	_, fail, err := doCompile(procCtx, log, req.Files)
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

func (cs *CerbosPlaygroundService) PlaygroundTest(ctx context.Context, req *requestv1.PlaygroundTestRequest) (*responsev1.PlaygroundTestResponse, error) {
	log := logging.ReqScopeLog(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	comps, fail, err := doCompile(procCtx, log, req.Files)
	if err != nil {
		return nil, err
	}

	if fail != nil {
		return &responsev1.PlaygroundTestResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundTestResponse_Failure{
				Failure: fail,
			},
		}, nil
	}

	eng, err := comps.mkEngine(procCtx)
	if err != nil {
		log.Error("Failed to create engine", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to create engine")
	}

	fsys, err := buildFS(log, req.Files)
	if err != nil {
		return nil, err
	}

	results, err := verify.Verify(procCtx, fsys, eng, verify.Config{Trace: true})
	if err != nil {
		log.Error("Failed to run tests", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to run tests")
	}

	return &responsev1.PlaygroundTestResponse{
		PlaygroundId: req.PlaygroundId,
		Outcome: &responsev1.PlaygroundTestResponse_Success{
			Success: &responsev1.PlaygroundTestResponse_TestResults{
				Results: results,
			},
		},
	}, nil
}

func (cs *CerbosPlaygroundService) PlaygroundEvaluate(ctx context.Context, req *requestv1.PlaygroundEvaluateRequest) (*responsev1.PlaygroundEvaluateResponse, error) {
	log := logging.ReqScopeLog(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	comps, fail, err := doCompile(procCtx, log, req.Files)
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

	auxData, err := cs.auxData.Extract(ctx, req.AuxData)
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "failed to extract auxData")
	}

	eng, err := comps.mkEngine(procCtx)
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
			AuxData:   auxData,
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
	log := logging.ReqScopeLog(ctx).Named("playground")

	procCtx, cancelFunc := context.WithTimeout(ctx, playgroundRequestTimeout)
	defer cancelFunc()

	comps, fail, err := doCompile(procCtx, log, req.Files)
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

	eng, err := comps.mkEngine(procCtx)
	if err != nil {
		log.Error("Failed to create engine", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to create engine")
	}

	cerbosSvc := NewCerbosService(eng, cs.auxData, cs.reqLimits)
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
	case *requestv1.PlaygroundProxyRequest_PlanResources:
		resp, err := cerbosSvc.PlanResources(ctx, proxyReq.PlanResources)
		if err != nil {
			return nil, err
		}

		return &responsev1.PlaygroundProxyResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundProxyResponse_PlanResources{
				PlanResources: resp,
			},
		}, nil
	case *requestv1.PlaygroundProxyRequest_CheckResources:
		resp, err := cerbosSvc.CheckResources(ctx, proxyReq.CheckResources)
		if err != nil {
			return nil, err
		}

		return &responsev1.PlaygroundProxyResponse{
			PlaygroundId: req.PlaygroundId,
			Outcome: &responsev1.PlaygroundProxyResponse_CheckResources{
				CheckResources: resp,
			},
		}, nil

	default:
		log.Error(fmt.Sprintf("Unhandled playground proxy request type %T", proxyReq))
		return nil, status.Error(codes.Unimplemented, "unknown request type")
	}
}

func doCompile(ctx context.Context, log *zap.Logger, files []*requestv1.File) (*components, *responsev1.PlaygroundFailure, error) {
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

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementWarn))

	if err := compile.BatchCompile(idx.GetAllCompilationUnits(ctx), schemaMgr); err != nil {
		compErr := new(compile.ErrorSet)
		if errors.As(err, &compErr) {
			pf := processCompileErrors(ctx, compErr)
			return nil, pf, nil
		}

		log.Error("Failed to compile", zap.Error(err))
		return nil, nil, status.Errorf(codes.Internal, "failed to compile")
	}

	return &components{idx: idx, store: store, schemaMgr: schemaMgr}, nil, nil
}

func buildIndex(ctx context.Context, log *zap.Logger, files []*requestv1.File) (index.Index, error) {
	fsys, err := buildFS(log, files)
	if err != nil {
		return nil, err
	}

	return index.Build(ctx, fsys)
}

func buildFS(log *zap.Logger, files []*requestv1.File) (fs.FS, error) {
	fsys := afero.NewMemMapFs()
	for _, file := range files {
		if err := afero.WriteFile(fsys, file.FileName, file.Contents, 0o644); err != nil { //nolint:mnd
			log.Error("Failed to create in-mem file", zap.String("file", file.FileName), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "failed to create file %s", file.FileName)
		}
	}

	return afero.NewIOFS(fsys), nil
}

func processLintErrors(ctx context.Context, errs *index.BuildError) *responsev1.PlaygroundFailure {
	var errors []*responsev1.PlaygroundFailure_Error //nolint:prealloc

	for _, dd := range errs.DuplicateDefs {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  dd.File,
			Error: fmt.Sprintf("Policy %s is defined in both %s and %s", dd.Policy, dd.File, dd.OtherFile),
			Details: &responsev1.PlaygroundFailure_ErrorDetails{
				Line:   dd.GetPosition().GetLine(),
				Column: dd.GetPosition().GetColumn(),
			},
		})
	}

	for _, mi := range errs.MissingImports {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  mi.ImportingFile,
			Error: mi.Desc,
			Details: &responsev1.PlaygroundFailure_ErrorDetails{
				Line:   mi.GetPosition().GetLine(),
				Column: mi.GetPosition().GetColumn(),
			},
		})
	}

	for _, missingScopes := range errs.MissingScopeDetails {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			Error: fmt.Sprintf(
				"Scoped policy %s is not found but is required by descendant policies %s",
				missingScopes.MissingPolicy,
				strings.Join(missingScopes.Descendants, ", "),
			),
		})
	}

	for _, lf := range errs.LoadFailures {
		var details *responsev1.PlaygroundFailure_ErrorDetails
		var msg string
		if ed := lf.GetErrorDetails(); ed != nil {
			msg = fmt.Sprintf("Failed to read: %s", ed.GetMessage())
			details = &responsev1.PlaygroundFailure_ErrorDetails{
				Line:    ed.GetPosition().GetLine(),
				Column:  ed.GetPosition().GetColumn(),
				Context: ed.GetContext(),
			}
		} else {
			msg = fmt.Sprintf("Failed to read: %s", lf.Error) //nolint:staticcheck
		}

		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:    lf.File,
			Error:   msg,
			Details: details,
		})
	}

	for _, d := range errs.DisabledDefs {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			File:  d.File,
			Error: fmt.Sprintf("Disabled policy: %s", d.Policy),
			Details: &responsev1.PlaygroundFailure_ErrorDetails{
				Line:   d.GetPosition().GetLine(),
				Column: d.GetPosition().GetColumn(),
			},
		})
	}

	for _, scopePermissionConflict := range errs.ScopePermissionsConflicts {
		errors = append(errors, &responsev1.PlaygroundFailure_Error{
			Error: fmt.Sprintf(
				"Policies sharing scope %s have conflicting scopePermissions\n",
				scopePermissionConflict.Scope,
			),
		})
	}

	SetHTTPStatusCode(ctx, http.StatusBadRequest)

	return &responsev1.PlaygroundFailure{Errors: errors}
}

func processCompileErrors(ctx context.Context, errs *compile.ErrorSet) *responsev1.PlaygroundFailure {
	compileErrs := errs.Errors().GetErrors()
	errors := make([]*responsev1.PlaygroundFailure_Error, len(compileErrs))

	for i, err := range compileErrs {
		errors[i] = &responsev1.PlaygroundFailure_Error{
			File:  err.File,
			Error: fmt.Sprintf("%s (%s)", err.Description, err.Error),
			Details: &responsev1.PlaygroundFailure_ErrorDetails{
				Line:    err.GetPosition().GetLine(),
				Column:  err.GetPosition().GetColumn(),
				Context: err.GetContext(),
			},
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
			Action: action,
			Effect: effect.Effect,
			Policy: effect.Policy,
		})
	}

	return &responsev1.PlaygroundEvaluateResponse{
		PlaygroundId: playgroundID,
		Outcome: &responsev1.PlaygroundEvaluateResponse_Success{
			Success: &responsev1.PlaygroundEvaluateResponse_EvalResultList{
				Results:               results,
				EffectiveDerivedRoles: outputs[0].EffectiveDerivedRoles,
				ValidationErrors:      outputs[0].ValidationErrors,
				Outputs:               outputs[0].Outputs,
			},
		},
	}, nil
}

type components struct {
	idx       index.Index
	store     storage.SourceStore
	schemaMgr schema.Manager
}

func (c *components) mkEngine(ctx context.Context) (*engine.Engine, error) {
	cm, err := compile.NewManager(ctx, c.store, c.schemaMgr)
	if err != nil {
		return nil, err
	}

	rt := ruletable.NewProtoRuletable()

	if err := ruletable.Load(ctx, rt, cm, c.store); err != nil {
		return nil, err
	}

	ruletableMgr, err := ruletable.NewRuleTableManager(rt, cm, c.store, c.schemaMgr)
	if err != nil {
		return nil, err
	}

	return engine.NewEphemeral(nil, ruletableMgr, c.schemaMgr), nil
}
