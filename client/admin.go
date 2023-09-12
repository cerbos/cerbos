// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/validator"
)

const (
	addPolicyBatchSize = 10
	addSchemaBatchSize = 10
)

type AdminClient interface {
	AddOrUpdatePolicy(ctx context.Context, policies *PolicySet) error
	AuditLogs(ctx context.Context, opts AuditLogOptions) (<-chan *AuditLogEntry, error)
	ListPolicies(ctx context.Context, opts ...ListPoliciesOption) ([]string, error)
	GetPolicy(ctx context.Context, ids ...string) ([]*policyv1.Policy, error)
	DisablePolicy(ctx context.Context, ids ...string) (uint32, error)
	EnablePolicy(ctx context.Context, ids ...string) (uint32, error)
	AddOrUpdateSchema(ctx context.Context, schemas *SchemaSet) error
	DeleteSchema(ctx context.Context, ids ...string) (uint32, error)
	ListSchemas(ctx context.Context) ([]string, error)
	GetSchema(ctx context.Context, ids ...string) ([]*schemav1.Schema, error)
	ReloadStore(ctx context.Context, wait bool) error
}

// NewAdminClient creates a new admin client.
// It will look for credentials in the following order:
// - Environment: CERBOS_USERNAME and CERBOS_PASSWORD
// - Netrc file (~/.netrc if an override is not defined in the NETRC environment variable)
//
// Note that Unix domain socket connections cannot fallback to netrc and require either the
// environment variables to be defined or the credentials to provided explicitly via the
// NewAdminClientWithCredentials function.
func NewAdminClient(address string, opts ...Opt) (AdminClient, error) {
	return NewAdminClientWithCredentials(address, "", "", opts...)
}

// NewAdminClientWithCredentials creates a new admin client using credentials explicitly passed as arguments.
func NewAdminClientWithCredentials(address, username, password string, opts ...Opt) (AdminClient, error) {
	// TODO: handle this in call site
	target, user, pass, err := loadBasicAuthData(osEnvironment{}, address, username, password)
	if err != nil {
		return nil, err
	}

	grpcConn, conf, err := mkConn(target, opts...)
	if err != nil {
		return nil, err
	}

	basicAuth := newBasicAuthCredentials(user, pass)
	if conf.plaintext {
		basicAuth = basicAuth.Insecure()
	}

	return &GrpcAdminClient{client: svcv1.NewCerbosAdminServiceClient(grpcConn), creds: basicAuth}, nil
}

type GrpcAdminClient struct {
	client svcv1.CerbosAdminServiceClient
	creds  credentials.PerRPCCredentials
}

func (c *GrpcAdminClient) AddOrUpdatePolicy(ctx context.Context, policies *PolicySet) error {
	if err := policies.Validate(); err != nil {
		return err
	}

	all := policies.policies

	for bs := 0; bs < len(all); bs += addPolicyBatchSize {
		be := bs + addPolicyBatchSize
		if be >= len(all) {
			be = len(all)
		}

		req := &requestv1.AddOrUpdatePolicyRequest{Policies: all[bs:be]}
		if _, err := c.client.AddOrUpdatePolicy(ctx, req, grpc.PerRPCCredentials(c.creds)); err != nil {
			return fmt.Errorf("failed to send batch [%d,%d): %w", bs, be, err)
		}
	}

	return nil
}

type recvFn func() (*responsev1.ListAuditLogEntriesResponse, error)

// collectLogs collects logs from the receiver function and passes to the channel
// it will return an error if the channel type is not accepted.
func collectLogs(receiver recvFn) (<-chan *AuditLogEntry, error) {
	ch := make(chan *AuditLogEntry)

	go func() {
		defer close(ch)

		for {
			entry, err := receiver()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}

				ch <- &AuditLogEntry{err: err}
				return
			}

			ch <- &AuditLogEntry{
				accessLog:   entry.GetAccessLogEntry(),
				decisionLog: entry.GetDecisionLogEntry(),
			}
		}
	}()

	return ch, nil
}

func (c *GrpcAdminClient) AuditLogs(ctx context.Context, opts AuditLogOptions) (<-chan *AuditLogEntry, error) {
	resp, err := c.auditLogs(ctx, opts)
	if err != nil {
		return nil, err
	}

	return collectLogs(resp.Recv)
}

func (c *GrpcAdminClient) auditLogs(ctx context.Context, opts AuditLogOptions) (svcv1.CerbosAdminService_ListAuditLogEntriesClient, error) {
	var req *requestv1.ListAuditLogEntriesRequest
	switch opts.Type {
	case AccessLogs:
		req = &requestv1.ListAuditLogEntriesRequest{Kind: requestv1.ListAuditLogEntriesRequest_KIND_ACCESS}
	case DecisionLogs:
		req = &requestv1.ListAuditLogEntriesRequest{Kind: requestv1.ListAuditLogEntriesRequest_KIND_DECISION}
	default:
		return nil, errors.New("incorrect audit log type")
	}

	switch {
	case opts.Tail > 0:
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Tail{Tail: opts.Tail}
	case !opts.StartTime.IsZero() && !opts.EndTime.IsZero():
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Between{
			Between: &requestv1.ListAuditLogEntriesRequest_TimeRange{
				Start: timestamppb.New(opts.StartTime),
				End:   timestamppb.New(opts.EndTime),
			},
		}
	case opts.Lookup != "":
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Lookup{Lookup: opts.Lookup}
	}

	if err := validator.Validate(req); err != nil {
		return nil, err
	}

	resp, err := c.client.ListAuditLogEntries(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *GrpcAdminClient) ListPolicies(ctx context.Context, opts ...ListPoliciesOption) ([]string, error) {
	req := &requestv1.ListPoliciesRequest{}
	for _, opt := range opts {
		opt(req)
	}
	if err := validator.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate list policies request: %w", err)
	}

	p, err := c.client.ListPolicies(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not list policies: %w", err)
	}

	return p.PolicyIds, nil
}

func (c *GrpcAdminClient) GetPolicy(ctx context.Context, ids ...string) ([]*policyv1.Policy, error) {
	req := &requestv1.GetPolicyRequest{
		Id: ids,
	}
	if err := validator.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate get policy request: %w", err)
	}

	res, err := c.client.GetPolicy(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not get policy: %w", err)
	}

	return res.Policies, nil
}

func (c *GrpcAdminClient) DisablePolicy(ctx context.Context, ids ...string) (uint32, error) {
	req := &requestv1.DisablePolicyRequest{
		Id: ids,
	}
	if err := validator.Validate(req); err != nil {
		return 0, fmt.Errorf("could not validate disable policy request: %w", err)
	}

	resp, err := c.client.DisablePolicy(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return 0, fmt.Errorf("could not disable policy: %w", err)
	}

	return resp.DisabledPolicies, nil
}

func (c *GrpcAdminClient) EnablePolicy(ctx context.Context, ids ...string) (uint32, error) {
	req := &requestv1.EnablePolicyRequest{
		Id: ids,
	}
	if err := validator.Validate(req); err != nil {
		return 0, fmt.Errorf("could not validate enable policy request: %w", err)
	}

	resp, err := c.client.EnablePolicy(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return 0, fmt.Errorf("could not enable policy: %w", err)
	}

	return resp.EnabledPolicies, nil
}

func (c *GrpcAdminClient) AddOrUpdateSchema(ctx context.Context, schemas *SchemaSet) error {
	all := schemas.schemas
	for bs := 0; bs < len(all); bs += addSchemaBatchSize {
		be := bs + addSchemaBatchSize
		if be >= len(all) {
			be = len(all)
		}

		req := &requestv1.AddOrUpdateSchemaRequest{Schemas: all[bs:be]}
		if _, err := c.client.AddOrUpdateSchema(ctx, req, grpc.PerRPCCredentials(c.creds)); err != nil {
			return fmt.Errorf("failed to send batch [%d,%d): %w", bs, be, err)
		}
	}

	return nil
}

func (c *GrpcAdminClient) DeleteSchema(ctx context.Context, ids ...string) (uint32, error) {
	req := &requestv1.DeleteSchemaRequest{
		Id: ids,
	}
	if err := validator.Validate(req); err != nil {
		return 0, fmt.Errorf("could not validate delete schema request: %w", err)
	}

	resp, err := c.client.DeleteSchema(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return 0, fmt.Errorf("could not delete schema: %w", err)
	}

	return resp.DeletedSchemas, nil
}

func (c *GrpcAdminClient) ListSchemas(ctx context.Context) ([]string, error) {
	req := &requestv1.ListSchemasRequest{}
	if err := validator.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate list schemas request: %w", err)
	}

	s, err := c.client.ListSchemas(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not list schemas: %w", err)
	}

	return s.SchemaIds, nil
}

func (c *GrpcAdminClient) GetSchema(ctx context.Context, ids ...string) ([]*schemav1.Schema, error) {
	req := &requestv1.GetSchemaRequest{
		Id: ids,
	}
	if err := validator.Validate(req); err != nil {
		return nil, fmt.Errorf("could not validate get schema request: %w", err)
	}

	res, err := c.client.GetSchema(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not get schema: %w", err)
	}

	return res.Schemas, nil
}

func (c *GrpcAdminClient) ReloadStore(ctx context.Context, wait bool) error {
	req := &requestv1.ReloadStoreRequest{
		Wait: wait,
	}
	if err := validator.Validate(req); err != nil {
		return fmt.Errorf("could not validate reload store request: %w", err)
	}

	_, err := c.client.ReloadStore(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return fmt.Errorf("could not reload store: %w", err)
	}

	return nil
}
