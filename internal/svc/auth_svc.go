// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/auth"
)

var _ svcv1.CerbosAuthServiceServer = (*CerbosAuthService)(nil)

var AuthServicePath = "/" + svcv1.CerbosAuthService_ServiceDesc.ServiceName + "/Login"

type TokenGenerator interface {
	GenerateToken(username string) (string, error)
}

type Authenticator interface {
	Authenticate(username, password string) error
}

type CredentialChecker interface {
	// CheckCredentials checks the credentials from context, if role is not required
	// use empty string
	CheckCredentials(ctx context.Context, requiredRole auth.Role) error
}

// CerbosService implements the policy checking service.
type CerbosAuthService struct {
	*svcv1.UnimplementedCerbosAuthServiceServer
	authenticator  Authenticator
	tokenGenerator TokenGenerator
}

func NewCerbosAuthService(a Authenticator, g TokenGenerator) *CerbosAuthService {
	return &CerbosAuthService{
		UnimplementedCerbosAuthServiceServer: &svcv1.UnimplementedCerbosAuthServiceServer{},
		authenticator:                        a,
		tokenGenerator:                       g,
	}
}

func (cas *CerbosAuthService) Login(ctx context.Context, req *requestv1.LoginRequest) (*responsev1.LoginResponse, error) {
	if err := cas.authenticator.Authenticate(req.Username, req.Password); err != nil {
		return nil, err
	}

	token, err := cas.tokenGenerator.GenerateToken(req.Username)
	if err != nil {
		return nil, err
	}

	return &responsev1.LoginResponse{
		Token: token,
	}, nil
}
