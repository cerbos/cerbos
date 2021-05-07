// Copyright 2021 Zenauth Ltd.

package svc

import (
	"context"
	"errors"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cerbos/cerbos/internal/engine"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
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

func (cs *CerbosService) CheckResourceBatch(ctx context.Context, req *requestv1.CheckResourceBatchRequest) (*responsev1.CheckResourceBatchResponse, error) {
	log := ctxzap.Extract(ctx)

	result, err := cs.eng.CheckResourceBatch(logging.ToContext(ctx, log), req)
	if err != nil {
		if errors.Is(err, engine.ErrNoPoliciesMatched) {
			log.Info("No policies matched")
			return result, nil
		}

		log.Error("Policy check failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Policy execution failed")
	}

	return result, nil
}
