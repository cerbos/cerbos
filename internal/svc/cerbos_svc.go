package svc

import (
	"context"
	"errors"
	"net/http"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cerbos/cerbos/internal/engine"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
)

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

func (cs *CerbosService) Check(ctx context.Context, req *requestv1.CheckRequest) (*responsev1.CheckResponse, error) {
	log := ctxzap.Extract(ctx)

	result, err := cs.eng.Check(logging.ToContext(ctx, log), req)
	if err != nil {
		if errors.Is(err, engine.ErrNoPoliciesMatched) {
			log.Info("No policies matched")
			return newResponse(req.RequestId, http.StatusUnauthorized, "No policies matched", result), nil
		}

		log.Error("Policy check failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Policy execution failed")
	}

	switch result.Effect {
	case sharedv1.Effect_EFFECT_ALLOW:
		return newResponse(req.RequestId, http.StatusOK, "Allow", result), nil
	default:
		return newResponse(req.RequestId, http.StatusUnauthorized, "Deny", result), nil
	}
}

func newResponse(requestID string, code int, msg string, result *engine.CheckResult) *responsev1.CheckResponse {
	return &responsev1.CheckResponse{
		RequestId:     requestID,
		StatusCode:    uint32(code),
		StatusMessage: msg,
		Effect:        result.Effect,
		Meta:          result.Meta,
	}
}
