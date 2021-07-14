// Copyright 2021 Zenauth Ltd.

package client

import (
	"context"

	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"google.golang.org/grpc/credentials"
)

type AdminClient interface {
	AddOrUpdatePolicy(context.Context, ...*Policy) error
}

func NewAdminClient(address string, opts ...Opt) (AdminClient, error) {
	return NewAdminClientWithCredentials(address, "", "", opts...)
}

func NewAdminClientWithCredentials(address, username, password string, opts ...Opt) (AdminClient, error) {
	target, user, pass, err := loadBasicAuthData(osEnvironment{}, address, username, password)
	if err != nil {
		return nil, err
	}

	grpcConn, err := mkConn(target, opts...)
	if err != nil {
		return nil, err
	}

	basicAuth := newBasicAuthCredentials(user, pass)

	return &grpcAdminClient{client: svcv1.NewCerbosAdminServiceClient(grpcConn), creds: basicAuth}, nil
}

type grpcAdminClient struct {
	client svcv1.CerbosAdminServiceClient
	creds  credentials.PerRPCCredentials
}

func (gac *grpcAdminClient) AddOrUpdatePolicy(ctx context.Context, policies ...*Policy) error {
	return nil
}
