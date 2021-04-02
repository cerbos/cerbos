package svc

import (
	"context"
	"errors"
	"net/http"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cerbos/cerbos/pkg/engine"
	requestv1 "github.com/cerbos/cerbos/pkg/generated/request/v1"
	responsev1 "github.com/cerbos/cerbos/pkg/generated/response/v1"
	sharedv1 "github.com/cerbos/cerbos/pkg/generated/shared/v1"
	svcv1 "github.com/cerbos/cerbos/pkg/generated/svc/v1"
	"github.com/cerbos/cerbos/pkg/observability/logging"
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

	effect, err := cs.eng.Check(logging.ToContext(ctx, log), req)
	if err != nil {
		if errors.Is(err, engine.ErrNoPoliciesMatched) {
			log.Info("No policies matched")
			return newResponse(req.RequestId, http.StatusUnauthorized, "No policies matched", sharedv1.Effect_EFFECT_DENY), nil
		}

		log.Error("Policy check failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Policy execution failed")
	}

	log.Info("Policy decision made", zap.String("effect", sharedv1.Effect_name[int32(effect)]))

	switch effect {
	case sharedv1.Effect_EFFECT_ALLOW:
		return newResponse(req.RequestId, http.StatusOK, "Allow", effect), nil
	default:
		return newResponse(req.RequestId, http.StatusUnauthorized, "Deny", effect), nil
	}
}

func newResponse(requestID string, code int, msg string, effect sharedv1.Effect) *responsev1.CheckResponse {
	return &responsev1.CheckResponse{
		RequestId:     requestID,
		StatusCode:    uint32(code),
		StatusMessage: msg,
		Effect:        effect,
	}
}
