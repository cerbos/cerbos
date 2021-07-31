// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
)

type AdminClient interface {
	AddOrUpdatePolicy(context.Context, *PolicySet) error
	AccessLogs(ctx context.Context, opts AuditLogOptions) ([]*auditv1.AccessLogEntry, error)
	DecisionLogs(ctx context.Context, opts AuditLogOptions) ([]*auditv1.DecisionLogEntry, error)
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

// AuditLogOptions is used to filter audit logs
type AuditLogOptions struct {
	Tail      uint16
	StartTime time.Time
	EndTime   time.Time
	Lookup    string
}

type logSet struct {
	accessLogs   []*auditv1.AccessLogEntry
	decisionLogs []*auditv1.DecisionLogEntry
}

// AccessLogs returns audit logs of the access type entries
func (c *GrpcAdminClient) AccessLogs(ctx context.Context, opts AuditLogOptions) ([]*auditv1.AccessLogEntry, error) {
	logs, err := c.auditLogs(ctx, requestv1.ListAuditLogEntriesRequest_KIND_ACCESS, opts)
	if err != nil {
		return nil, err
	}

	return logs.accessLogs, nil
}

// DecisionLogs returns decision logs of the decision type entries
func (c *GrpcAdminClient) DecisionLogs(ctx context.Context, opts AuditLogOptions) ([]*auditv1.DecisionLogEntry, error) {
	logs, err := c.auditLogs(ctx, requestv1.ListAuditLogEntriesRequest_KIND_DECISION, opts)
	if err != nil {
		return nil, err
	}

	return logs.decisionLogs, nil
}

func (c *GrpcAdminClient) auditLogs(ctx context.Context, kind requestv1.ListAuditLogEntriesRequest_Kind, opts AuditLogOptions) (*logSet, error) {
	req := &requestv1.ListAuditLogEntriesRequest{Kind: kind}

	switch {
	case opts.Tail > 0:
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Tail{Tail: uint32(opts.Tail)}
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

	resp, err := c.client.ListAuditLogEntries(ctx, req, grpc.PerRPCCredentials(c.creds))
	if err != nil {
		return nil, err
	}

	entries := &logSet{
		accessLogs:   make([]*auditv1.AccessLogEntry, 0),
		decisionLogs: make([]*auditv1.DecisionLogEntry, 0),
	}

	for {
		entry, err := resp.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println("entries... done")
				return entries, nil
			}

			return nil, err
		}

		fmt.Println("adding entry")
		switch kind {
		case requestv1.ListAuditLogEntriesRequest_KIND_ACCESS:
			entries.accessLogs = append(entries.accessLogs, entry.GetAccessLogEntry())
		case requestv1.ListAuditLogEntriesRequest_KIND_DECISION:
			entries.decisionLogs = append(entries.decisionLogs, entry.GetDecisionLogEntry())
		default:
			return nil, fmt.Errorf("unsupported audit log entry kind: %s", kind)
		}
	}
}
