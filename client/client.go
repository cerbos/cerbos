// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package client provides a client implementation to interact with a Cerbos instance and check access policies.
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
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/util"
)

// Client provides access to the Cerbos API.
type Client interface {
	// IsAllowed checks access to a single resource by a principal and returns true if access is granted.
	IsAllowed(ctx context.Context, principal *Principal, resource *Resource, action string) (bool, error)
	// CheckResourceSet checks access to a set of resources of the same kind.
	// Deprecated: Use CheckResources instead.
	CheckResourceSet(ctx context.Context, principal *Principal, resources *ResourceSet, actions ...string) (*CheckResourceSetResponse, error)
	// CheckResourceBatch checks access to a batch of resources of different kinds.
	// Deprecated: Use CheckResources instead.
	CheckResourceBatch(ctx context.Context, principal *Principal, resources *ResourceBatch) (*CheckResourceBatchResponse, error)
	// CheckResources checks access to a batch of resources of different kinds.
	CheckResources(ctx context.Context, principal *Principal, resources *ResourceBatch) (*CheckResourcesResponse, error)
	// ServerInfo retrieves server information.
	ServerInfo(ctx context.Context) (*ServerInfo, error)
	// With sets per-request options for the client.
	With(opts ...RequestOpt) Client
	// ResourcesQueryPlan gets resources query plan for the given principal, resource and action.
	ResourcesQueryPlan(ctx context.Context, principal *Principal, resource *Resource, action string) (*ResourcesQueryPlanResponse, error)
	// WithPrincipal sets the principal to be used for subsequent API calls.
	WithPrincipal(principal *Principal) PrincipalContext
}

// PrincipalContext provides convenience methods to access the Cerbos API in the context of a single principal.
type PrincipalContext interface {
	// Principal returns the principal attached to this context.
	Principal() *Principal
	// IsAllowed checks access to a single resource by the principal and returns true if access is granted.
	IsAllowed(ctx context.Context, resource *Resource, action string) (bool, error)
	// CheckResources checks access to a batch of resources of different kinds.
	CheckResources(ctx context.Context, resources *ResourceBatch) (*CheckResourcesResponse, error)
	// ResourcesQueryPlan gets resources query plan for the given resource and action.
	ResourcesQueryPlan(ctx context.Context, resource *Resource, action string) (*ResourcesQueryPlanResponse, error)
}

type config struct {
	address            string
	tlsAuthority       string
	tlsCACert          string
	tlsClientCert      string
	tlsClientKey       string
	userAgent          string
	playgroundInstance string
	connectTimeout     time.Duration
	retryTimeout       time.Duration
	maxRetries         uint
	plaintext          bool
	tlsInsecure        bool
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

// WithUserAgent sets the user agent string.
func WithUserAgent(ua string) Opt {
	return func(c *config) {
		c.userAgent = ua
	}
}

// WithPlaygroundInstance sets the Cerbos playground instance to use as the source of policies.
// Note that Playground instances are for demonstration purposes only and do not provide any
// performance or availability guarantees.
func WithPlaygroundInstance(instance string) Opt {
	return func(c *config) {
		c.playgroundInstance = instance
	}
}

// New creates a new Cerbos client.
func New(address string, opts ...Opt) (Client, error) {
	grpcConn, _, err := mkConn(address, opts...)
	if err != nil {
		return nil, err
	}

	return &grpcClient{stub: svcv1.NewCerbosServiceClient(grpcConn)}, nil
}

func mkConn(address string, opts ...Opt) (*grpc.ClientConn, *config, error) {
	conf := &config{
		address:        address,
		connectTimeout: 30 * time.Second, //nolint:gomnd
		maxRetries:     3,                //nolint:gomnd
		retryTimeout:   2 * time.Second,  //nolint:gomnd
		userAgent:      fmt.Sprintf("cerbos-client/%s", util.Version),
	}

	for _, o := range opts {
		o(conf)
	}

	dialOpts, err := mkDialOpts(conf)
	if err != nil {
		return nil, nil, err
	}

	grpcConn, err := grpc.Dial(conf.address, dialOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial gRPC: %w", err)
	}

	return grpcConn, conf, nil
}

func mkDialOpts(conf *config) ([]grpc.DialOption, error) {
	dialOpts := []grpc.DialOption{grpc.WithUserAgent(conf.userAgent)}

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

	if conf.playgroundInstance != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(newPlaygroundInstanceCredentials(conf.playgroundInstance)))
	}

	return dialOpts, nil
}

func mkTLSConfig(conf *config) (*tls.Config, error) {
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
	opts *reqOpt
}

func (gc *grpcClient) ResourcesQueryPlan(ctx context.Context, principal *Principal, resource *Resource, action string) (*ResourcesQueryPlanResponse, error) {
	if err := isValid(principal); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	// ResourceQueryPlan.Resource object doesn't have an ID field, since it doesn't describe a concrete instance,
	// but a set of resources. To workaround resource validation we assign a dummyID to resource.r.Id field,
	// in case it is empty.
	if resource != nil && resource.r != nil && resource.r.Id == "" {
		resource.r.Id = "dummyID"
	}

	if err := isValid(resource); err != nil {
		return nil, fmt.Errorf("invalid resource: %w", err)
	}

	reqID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	req := &requestv1.ResourcesQueryPlanRequest{
		RequestId: reqID.String(),
		Action:    action,
		Principal: principal.p,
		Resource: &enginev1.ResourcesQueryPlanRequest_Resource{
			Kind:          resource.r.Kind,
			Attr:          resource.r.Attr,
			PolicyVersion: resource.r.PolicyVersion,
		},
	}

	if gc.opts != nil {
		req.AuxData = gc.opts.auxData
		req.IncludeMeta = gc.opts.includeMeta
	}

	result, err := gc.stub.ResourcesQueryPlan(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &ResourcesQueryPlanResponse{ResourcesQueryPlanResponse: result}, nil
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
		Principal: principal.p,
		Resource:  resourceSet.rs,
	}

	if gc.opts != nil {
		req.AuxData = gc.opts.auxData
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
		Principal: principal.p,
		Resources: resourceBatch.toResourceBatchEntry(),
	}

	if gc.opts != nil {
		req.AuxData = gc.opts.auxData
	}

	result, err := gc.stub.CheckResourceBatch(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &CheckResourceBatchResponse{CheckResourceBatchResponse: result}, nil
}

func (gc *grpcClient) CheckResources(ctx context.Context, principal *Principal, resourceBatch *ResourceBatch) (*CheckResourcesResponse, error) {
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

	req := &requestv1.CheckResourcesRequest{
		RequestId: reqID.String(),
		Principal: principal.p,
		Resources: resourceBatch.batch,
	}

	if gc.opts != nil {
		req.AuxData = gc.opts.auxData
	}

	result, err := gc.stub.CheckResources(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return &CheckResourcesResponse{CheckResourcesResponse: result}, nil
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

	req := &requestv1.CheckResourcesRequest{
		RequestId: reqID.String(),
		Principal: principal.p,
		Resources: []*requestv1.CheckResourcesRequest_ResourceEntry{
			{Actions: []string{action}, Resource: resource.r},
		},
	}

	if gc.opts != nil {
		req.AuxData = gc.opts.auxData
	}

	result, err := gc.stub.CheckResources(ctx, req)
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
},
) error {
	if err := obj.Err(); err != nil {
		return err
	}

	return obj.Validate()
}

func (gc *grpcClient) ServerInfo(ctx context.Context) (*ServerInfo, error) {
	resp, err := gc.stub.ServerInfo(ctx, &requestv1.ServerInfoRequest{})
	if err != nil {
		return nil, err
	}
	return &ServerInfo{
		ServerInfoResponse: resp,
	}, nil
}

func (gc *grpcClient) With(reqOpts ...RequestOpt) Client {
	opts := &reqOpt{}
	for _, ro := range reqOpts {
		ro(opts)
	}

	return &grpcClient{opts: opts, stub: gc.stub}
}

func (gc *grpcClient) WithPrincipal(p *Principal) PrincipalContext {
	return &grpcClientPrincipalCtx{client: gc, principal: p}
}

type grpcClientPrincipalCtx struct {
	client    *grpcClient
	principal *Principal
}

func (gcpc *grpcClientPrincipalCtx) Principal() *Principal {
	return gcpc.principal
}

func (gcpc *grpcClientPrincipalCtx) IsAllowed(ctx context.Context, resource *Resource, action string) (bool, error) {
	return gcpc.client.IsAllowed(ctx, gcpc.principal, resource, action)
}

func (gcpc *grpcClientPrincipalCtx) CheckResources(ctx context.Context, batch *ResourceBatch) (*CheckResourcesResponse, error) {
	return gcpc.client.CheckResources(ctx, gcpc.principal, batch)
}

func (gcpc *grpcClientPrincipalCtx) ResourcesQueryPlan(ctx context.Context, resource *Resource, action string) (*ResourcesQueryPlanResponse, error) {
	return gcpc.client.ResourcesQueryPlan(ctx, gcpc.principal, resource, action)

}
