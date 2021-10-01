// Copyright 2021 Zenauth Ltd.
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
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
)

type AdminClient interface {
	AddOrUpdatePolicy(context.Context, *PolicySet) error
	AuditLogs(ctx context.Context, opts AuditLogOptions) (<-chan *AuditLogEntry, error)
	// ListPolicies retrieves the policies on the Cerbos server.
	ListPolicies(ctx context.Context, opts ...ListOpt) ([]*policyv1.Policy, error)
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

	req := &requestv1.AddOrUpdatePolicyRequest{Policies: policies.policies}
	if _, err := c.client.AddOrUpdatePolicy(ctx, req, grpc.PerRPCCredentials(c.creds)); err != nil {
		return err
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

	if err := req.Validate(); err != nil {
		return nil, err
	}

	resp, err := c.client.ListAuditLogEntries(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *GrpcAdminClient) ListPolicies(ctx context.Context, opts ...ListOpt) ([]*policyv1.Policy, error) {
	listOptions := &policyListOptions{
		filters: make([]*requestv1.ListPoliciesRequest_Filter, 0, len(opts)),
	}
	for _, opt := range opts {
		opt(listOptions)
	}

	req := &requestv1.ListPoliciesRequest{
		Filters: listOptions.filters,
	}

	if listOptions.sortingOptions != nil {
		order := requestv1.ListPoliciesRequest_SortOptions_ORDER_ASCENDING
		if listOptions.sortingOptions.descending {
			order = requestv1.ListPoliciesRequest_SortOptions_ORDER_DESCENDING
		}
		req.SortOptions = &requestv1.ListPoliciesRequest_SortOptions{
			Order:  order,
			Column: requestv1.ListPoliciesRequest_SortOptions_Column(listOptions.sortingOptions.field),
		}
	}

	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("could not validate list policies request: %w", err)
	}

	pc, err := c.client.ListPolicies(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, fmt.Errorf("could not list policies: %w", err)
	}

	return pc.Policies, nil
}
