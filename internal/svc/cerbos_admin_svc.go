// Copyright 2021 Zenauth Ltd.

package svc

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
)

var _ svcv1.CerbosAdminServiceServer = (*CerbosAdminService)(nil)

var (
	errAuthRequired = status.Error(codes.Unauthenticated, "authentication required")
	authSep         = []byte(":")
)

// CerbosAdminService implements the Cerbos administration service.
type CerbosAdminService struct {
	store           storage.MutableStore
	adminUser       string
	adminPasswdHash []byte
	*svcv1.UnimplementedCerbosAdminServiceServer
}

func NewCerbosAdminService(store storage.Store, adminUser, adminPasswdHash string) *CerbosAdminService {
	svc := &CerbosAdminService{
		adminUser:                             adminUser,
		adminPasswdHash:                       []byte(adminPasswdHash),
		UnimplementedCerbosAdminServiceServer: &svcv1.UnimplementedCerbosAdminServiceServer{},
	}

	ms, ok := store.(storage.MutableStore)
	if ok {
		svc.store = ms
	}

	return svc
}

func (cas *CerbosAdminService) AddOrUpdatePolicy(ctx context.Context, req *requestv1.AddOrUpdatePolicyRequest) (*responsev1.AddOrUpdatePolicyResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

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

func (cas *CerbosAdminService) checkCredentials(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errAuthRequired
	}

	header, ok := md["authorization"]
	if !ok || len(header) == 0 {
		return errAuthRequired
	}

	if !strings.HasPrefix(header[0], "Basic") {
		return status.Error(codes.Unauthenticated, "unsupported authentication method")
	}

	encoded := strings.TrimSpace(strings.TrimPrefix(header[0], "Basic"))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return status.Error(codes.Unauthenticated, "failed to decode credentials")
	}

	parts := bytes.Split(decoded, authSep)
	if len(parts) != 2 { //nolint:gomnd
		return status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if !bytes.Equal(parts[0], []byte(cas.adminUser)) {
		return status.Error(codes.Unauthenticated, "incorrect credentials")
	}

	if err := bcrypt.CompareHashAndPassword(cas.adminPasswdHash, parts[1]); err != nil {
		return status.Error(codes.Unauthenticated, "invalid credentials")
	}

	return nil
}
