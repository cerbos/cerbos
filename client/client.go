// Copyright 2021 Zenauth Ltd.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/util"
)

// Client provides access to the Cerbos API.
type Client interface {
	// IsAllowed checks access to a single resource by a principal and returns true if access is granted.
	IsAllowed(context.Context, *Principal, *Resource, string) (bool, error)
	// CheckResourceSet checks access to a set of resources of the same kind.
	CheckResourceSet(context.Context, *Principal, *ResourceSet, ...string) (*CheckResourceSetResponse, error)
	// CheckResourceBatch checks access to a batch of resources of different kinds.
	CheckResourceBatch(context.Context, *Principal, *ResourceBatch) (*CheckResourceBatchResponse, error)
}

type config struct {
	address        string
	plaintext      bool
	tlsAuthority   string
	tlsInsecure    bool
	tlsCACert      string
	tlsClientCert  string
	tlsClientKey   string
	connectTimeout time.Duration
	maxRetries     uint
	retryTimeout   time.Duration
}

type Opt func(*config)

// WithPlaintext configures the client to connect over h2c.
func WithPlaintext() Opt {
	return func(c *config) {
		c.plaintext = true
	}
}

// WithTLSAuthority overrides the remote server authority if it is different from what is provided in the address.
func WithTLSAuthority(authority string) Opt {
	return func(c *config) {
		c.tlsAuthority = authority
	}
}

// WithTLSInsecure enables skipping TLS certificate verification.
func WithTLSInsecure() Opt {
	return func(c *config) {
		c.tlsInsecure = true
	}
}

// WithTLSCACert sets the CA certificate chain to use for certificate verification.
func WithTLSCACert(certPath string) Opt {
	return func(c *config) {
		c.tlsCACert = certPath
	}
}

// WithTLSClientCert sets the client certificate to use to authenticate to the server.
func WithTLSClientCert(cert, key string) Opt {
	return func(c *config) {
		c.tlsClientCert = cert
		c.tlsClientKey = key
	}
}

// WithConnectTimeout sets the connection establishment timeout.
func WithConnectTimeout(timeout time.Duration) Opt {
	return func(c *config) {
		c.connectTimeout = timeout
	}
}

// WithMaxRetries sets the maximum number of retries per call.
func WithMaxRetries(retries uint) Opt {
	return func(c *config) {
		c.maxRetries = retries
	}
}

// WithRetryTimeout sets the timeout per retry attempt.
func WithRetryTimeout(timeout time.Duration) Opt {
	return func(c *config) {
		c.retryTimeout = timeout
	}
}

// New creates a new Cerbos client.
func New(address string, opts ...Opt) (Client, error) {
	grpcConn, err := mkConn(address, opts...)
	if err != nil {
		return nil, err
	}

	return &grpcClient{stub: svcv1.NewCerbosServiceClient(grpcConn)}, nil
}

func mkConn(address string, opts ...Opt) (*grpc.ClientConn, error) {
	conf := config{
		address:        address,
		connectTimeout: 30 * time.Second, //nolint:gomnd
		maxRetries:     3,                //nolint:gomnd
		retryTimeout:   2 * time.Second,  //nolint:gomnd
	}

	for _, o := range opts {
		o(&conf)
	}

	dialOpts, err := mkDialOpts(conf)
	if err != nil {
		return nil, err
	}

	grpcConn, err := grpc.Dial(conf.address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return grpcConn, nil
}

func mkDialOpts(conf config) ([]grpc.DialOption, error) {
	var dialOpts []grpc.DialOption

	if conf.connectTimeout > 0 {
		dialOpts = append(dialOpts, grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: conf.connectTimeout}))
	}

	if conf.maxRetries > 0 && conf.retryTimeout > 0 {
		dialOpts = append(dialOpts,
			grpc.WithChainStreamInterceptor(
				grpc_retry.StreamClientInterceptor(
					grpc_retry.WithMax(conf.maxRetries),
					grpc_retry.WithPerRetryTimeout(conf.retryTimeout),
				),
			),
			grpc.WithChainUnaryInterceptor(
				grpc_retry.UnaryClientInterceptor(
					grpc_retry.WithMax(conf.maxRetries),
					grpc_retry.WithPerRetryTimeout(conf.retryTimeout),
				),
			),
		)
	}

	if conf.plaintext {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(local.NewCredentials()))
	} else {
		tlsConf, err := mkTLSConfig(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		if conf.tlsAuthority != "" {
			dialOpts = append(dialOpts, grpc.WithAuthority(conf.tlsAuthority))
		}
	}

	return dialOpts, nil
}

func mkTLSConfig(conf config) (*tls.Config, error) {
	tlsConf := util.DefaultTLSConfig()

	if conf.tlsInsecure {
		tlsConf.InsecureSkipVerify = true
	}

	if conf.tlsCACert != "" {
		bs, err := os.ReadFile(conf.tlsCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate from %s: %w", conf.tlsCACert, err)
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return nil, errors.New("failed to append CA certificates to the pool")
		}

		tlsConf.RootCAs = certPool
	}

	if conf.tlsClientCert != "" && conf.tlsClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(conf.tlsClientCert, conf.tlsClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key from [%s, %s]: %w", conf.tlsClientCert, conf.tlsClientKey, err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
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

func (gc *grpcClient) CheckResourceBatch(ctx context.Context, principal *Principal, resourceBatch *ResourceBatch) (*CheckResourceBatchResponse, error) {
	if err := isValid(principal); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	if err := isValid(resourceBatch); err != nil {
		return nil, fmt.Errorf("invalid resource batch; %w", err)
	}

	reqID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	req := &requestv1.CheckResourceBatchRequest{
		RequestId: reqID.String(),
		Principal: principal.Principal,
		Resources: resourceBatch.batch,
	}

	result, err := gc.stub.CheckResourceBatch(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &CheckResourceBatchResponse{CheckResourceBatchResponse: result}, nil
}

func (gc *grpcClient) IsAllowed(ctx context.Context, principal *Principal, resource *Resource, action string) (bool, error) {
	if err := isValid(principal); err != nil {
		return false, fmt.Errorf("invalid principal: %w", err)
	}

	if err := isValid(resource); err != nil {
		return false, fmt.Errorf("invalid resource: %w", err)
	}

	reqID, err := uuid.NewRandom()
	if err != nil {
		return false, fmt.Errorf("failed to generate request ID: %w", err)
	}

	req := &requestv1.CheckResourceBatchRequest{
		RequestId: reqID.String(),
		Principal: principal.Principal,
		Resources: []*requestv1.CheckResourceBatchRequest_BatchEntry{
			{Actions: []string{action}, Resource: resource.Resource},
		},
	}

	result, err := gc.stub.CheckResourceBatch(ctx, req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}

	if len(result.Results) == 0 {
		return false, fmt.Errorf("unexpected response from server")
	}

	return result.Results[0].Actions[action] == effectv1.Effect_EFFECT_ALLOW, nil
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
