// Copyright 2021 Zenauth Ltd.

package svc

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
)

var _ svcv1.CerbosAdminServiceServer = (*CerbosAdminService)(nil)

// CerbosAdminService implements the Cerbos administration service.
type CerbosAdminService struct {
	store storage.MutableStore
	*svcv1.UnimplementedCerbosAdminServiceServer
}

func NewCerbosAdminService(store storage.Store) *CerbosAdminService {
	svc := &CerbosAdminService{UnimplementedCerbosAdminServiceServer: &svcv1.UnimplementedCerbosAdminServiceServer{}}

	ms, ok := store.(storage.MutableStore)
	if ok {
		svc.store = ms
	}

	return svc
}

func (cas *CerbosAdminService) AddOrUpdatePolicy(ctx context.Context, req *requestv1.AddOrUpdatePolicyRequest) (*responsev1.AddOrUpdatePolicyResponse, error) {
	log := ctxzap.Extract(ctx)
	if cas.store == nil {
		log.Warn("Ignoring call because the store is not mutable")
		return nil, status.Error(codes.Unimplemented, "Configured store is not mutable")
	}

	policies := make([]policy.Wrapper, len(req.Policies))
	for i, p := range req.Policies {
		policies[i] = policy.Wrap(p)
	}

	if err := cas.store.AddOrUpdate(ctx, policies...); err != nil {
		log.Error("Failed to add/update policies", zap.Error(err))
		return nil, status.Error(codes.Internal, "Failed to add/update policies")
	}

	return &responsev1.AddOrUpdatePolicyResponse{Success: &emptypb.Empty{}}, nil
}
