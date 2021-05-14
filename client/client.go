// Copyright 2021 Zenauth Ltd.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/util"
)

// Client provides access to the Cerbos API.
type Client interface {
	CheckResourceSet(context.Context, *Principal, *ResourceSet, ...string) (*CheckResourceSetResponse, error)
}

// Config for the client.
type Config struct {
	// Address is the server address to connect to. Supports gRPC naming conventions (https://github.com/grpc/grpc/blob/master/doc/naming.md).
	Address string
	// Plaintext indicates that this client should connect over h2c.
	Plaintext bool
	// TLSAuthority overrides the remote server authority if it is different from what is provided in the address.
	TLSAuthority string
	// TLSSkipVerify enables skipping TLS certificate verification.
	TLSSkipVerify bool
	// TLSCACert is the CA certificate chain to use for certificate verification.
	TLSCACert []byte
	// TLSClientCert is the TLS client certificate to use to authenticate to the remote server.
	TLSClientCert *tls.Certificate
	// ConnectTimeout is the time to wait before giving up on connecting to the remote server.
	ConnectTimeout time.Duration
	// Max retries is the number of retries to perform per RPC.
	MaxRetries uint
	// RetryTimeout is the timeout per retry attempt.
	RetryTimeout time.Duration
}

// New creates a new Cerbos client.
func New(conf *Config) (Client, error) {
	dialOpts := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: conf.ConnectTimeout}),
		grpc.WithChainStreamInterceptor(
			grpc_retry.StreamClientInterceptor(
				grpc_retry.WithMax(conf.MaxRetries),
				grpc_retry.WithPerRetryTimeout(conf.RetryTimeout),
			),
		),
		grpc.WithChainUnaryInterceptor(
			grpc_retry.UnaryClientInterceptor(
				grpc_retry.WithMax(conf.MaxRetries),
				grpc_retry.WithPerRetryTimeout(conf.RetryTimeout),
			),
		),
	}

	if conf.Plaintext {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(local.NewCredentials()))
	} else {
		tlsConf, err := mkTLSConfig(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		if conf.TLSAuthority != "" {
			dialOpts = append(dialOpts, grpc.WithAuthority(conf.TLSAuthority))
		}
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), conf.ConnectTimeout)
	defer cancelFunc()

	grpcConn, err := grpc.DialContext(ctx, conf.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return &grpcClient{stub: svcv1.NewCerbosServiceClient(grpcConn)}, nil
}

func mkTLSConfig(conf *Config) (*tls.Config, error) {
	tlsConf := util.DefaultTLSConfig()

	if conf.TLSSkipVerify {
		tlsConf.InsecureSkipVerify = true
	}

	if len(conf.TLSCACert) > 0 {
		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(conf.TLSCACert)
		if !ok {
			return nil, errors.New("failed to append certificates to the pool")
		}

		tlsConf.RootCAs = certPool
	}

	if conf.TLSClientCert != nil {
		tlsConf.Certificates = []tls.Certificate{*conf.TLSClientCert}
	}

	return tlsConf, nil
}

type grpcClient struct {
	stub svcv1.CerbosServiceClient
}

func (gc *grpcClient) CheckResourceSet(ctx context.Context, principal *Principal, resourceSet *ResourceSet, actions ...string) (*CheckResourceSetResponse, error) {
	if len(actions) == 0 {
		return nil, fmt.Errorf("at least one action must be specified")
	}

	if err := isValid(principal); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	if err := isValid(resourceSet); err != nil {
		return nil, fmt.Errorf("invalid resource set; %w", err)
	}

	reqID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	req := &requestv1.CheckResourceSetRequest{
		RequestId: reqID.String(),
		Actions:   actions,
		Principal: principal.Principal,
		Resource:  resourceSet.ResourceSet,
	}

	result, err := gc.stub.CheckResourceSet(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &CheckResourceSetResponse{CheckResourceSetResponse: result}, nil
}

func isValid(obj interface {
	Err() error
	Validate() error
}) error {
	if err := obj.Err(); err != nil {
		return err
	}

	return obj.Validate()
}
