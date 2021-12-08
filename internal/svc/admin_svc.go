// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/audit"
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
	store           storage.Store
	auditLog        audit.Log
	adminUser       string
	adminPasswdHash []byte
	*svcv1.UnimplementedCerbosAdminServiceServer
}

func NewCerbosAdminService(store storage.Store, auditLog audit.Log, adminUser string, adminPasswdHash []byte) *CerbosAdminService {
	svc := &CerbosAdminService{
		auditLog:                              auditLog,
		adminUser:                             adminUser,
		adminPasswdHash:                       adminPasswdHash,
		UnimplementedCerbosAdminServiceServer: &svcv1.UnimplementedCerbosAdminServiceServer{},
		store:                                 store,
	}

	return svc
}

func (cas *CerbosAdminService) AddOrUpdatePolicy(ctx context.Context, req *requestv1.AddOrUpdatePolicyRequest) (*responsev1.AddOrUpdatePolicyResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	ms, ok := cas.store.(storage.MutableStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store is not mutable")
	}

	policies := make([]policy.Wrapper, len(req.Policies))
	for i, p := range req.Policies {
		policies[i] = policy.Wrap(p)
	}

	log := ctxzap.Extract(ctx)
	if err := ms.AddOrUpdate(ctx, policies...); err != nil {
		log.Error("Failed to add/update policies", zap.Error(err))
		invalidPolicyErr := new(storage.InvalidPolicyError)
		if errors.As(err, invalidPolicyErr) {
			return nil, status.Errorf(codes.InvalidArgument, "Invalid policy: %v", invalidPolicyErr.Message)
		}
		return nil, status.Error(codes.Internal, "Failed to add/update policies")
	}

	return &responsev1.AddOrUpdatePolicyResponse{Success: &emptypb.Empty{}}, nil
}

func (cas *CerbosAdminService) AddOrUpdateSchema(ctx context.Context, req *requestv1.AddOrUpdateSchemaRequest) (*responsev1.AddOrUpdateSchemaResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	ms, ok := cas.store.(storage.MutableStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store is not mutable")
	}

	for _, sch := range req.Schemas {
		if err := ms.AddOrUpdateSchema(ctx, sch.Id, sch.Definition); err != nil {
			ctxzap.Extract(ctx).Error(fmt.Sprintf("Failed to add/update the schema with id %s", sch.Id), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "Failed to add/update the schema with id %s", sch.Id)
		}
	}

	return &responsev1.AddOrUpdateSchemaResponse{}, nil
}

func (cas *CerbosAdminService) ListSchemas(ctx context.Context, req *requestv1.ListSchemasRequest) (*responsev1.ListSchemasResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	schemaIds, err := cas.store.ListSchemaIDs(ctx)
	if err != nil {
		ctxzap.Extract(ctx).Error("Failed to list schema ids", zap.Error(err))
		return nil, status.Errorf(codes.NotFound, "failed to list schema ids: %s")
	}

	sortSchemas(schemaIds)

	return &responsev1.ListSchemasResponse{
		SchemaIds: schemaIds,
	}, nil
}

func (cas *CerbosAdminService) GetSchema(ctx context.Context, req *requestv1.GetSchemaRequest) (*responsev1.GetSchemaResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	log := ctxzap.Extract(ctx)

	schemas := make([]*schemav1.Schema, 0, len(req.Id))
	for _, id := range req.Id {
		sch, err := cas.store.LoadSchema(context.Background(), id)
		if err != nil {
			log.Error(fmt.Sprintf("Could not get the schema with id %s", id), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "could not get the schema with id %s", id)
		}

		schBytes, err := ioutil.ReadAll(sch)
		if err != nil {
			log.Error(fmt.Sprintf("Could not read the schema with id %s", id), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "could not read the schema with id %s", id)
		}

		schemas = append(schemas, &schemav1.Schema{
			Id:         id,
			Definition: schBytes,
		})
	}

	return &responsev1.GetSchemaResponse{
		Schemas: schemas,
	}, nil
}

func (cas *CerbosAdminService) DeleteSchema(ctx context.Context, req *requestv1.DeleteSchemaRequest) (*responsev1.DeleteSchemaResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	ms, ok := cas.store.(storage.MutableStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store is not mutable")
	}

	for _, id := range req.Id {
		if err := ms.DeleteSchema(ctx, id); err != nil {
			ctxzap.Extract(ctx).Error(fmt.Sprintf("Failed to delete the schema with id %s", id), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "Failed to delete the schema with id %s", id)
		}
	}

	return &responsev1.DeleteSchemaResponse{}, nil
}

func (cas *CerbosAdminService) ListAuditLogEntries(req *requestv1.ListAuditLogEntriesRequest, stream svcv1.CerbosAdminService_ListAuditLogEntriesServer) error {
	ctx := stream.Context()

	if err := cas.checkCredentials(ctx); err != nil {
		return err
	}

	logStream, err := cas.getAuditLogStream(ctx, req)
	if err != nil {
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		rec, err := logStream()
		if err != nil {
			if errors.Is(err, audit.ErrIteratorClosed) {
				return nil
			}

			ctxzap.Extract(ctx).Error("Error from log iterator", zap.Error(err))
			return status.Error(codes.Internal, "Iterator failure")
		}

		if err := stream.Send(rec); err != nil {
			ctxzap.Extract(ctx).Error("Error writing to stream", zap.Error(err))
			return err
		}
	}
}

func (cas *CerbosAdminService) ListPolicies(ctx context.Context, req *requestv1.ListPoliciesRequest) (*responsev1.ListPoliciesResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	units, err := cas.store.GetPolicies(context.Background())
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("could not get policies: %s", err.Error()))
	}

	policies, err := filterPolicies(req.Filters, units)
	if err != nil {
		return nil, err
	}

	sortPolicies(req.SortOptions, policies)

	return &responsev1.ListPoliciesResponse{
		Policies: policies,
	}, nil
}

func (cas *CerbosAdminService) getAuditLogStream(ctx context.Context, req *requestv1.ListAuditLogEntriesRequest) (auditLogStream, error) {
	switch req.Kind {
	case requestv1.ListAuditLogEntriesRequest_KIND_ACCESS:
		switch f := req.Filter.(type) {
		case *requestv1.ListAuditLogEntriesRequest_Tail:
			return mkAccessLogStream(cas.auditLog.LastNAccessLogEntries(ctx, uint(f.Tail))), nil
		case *requestv1.ListAuditLogEntriesRequest_Between:
			return mkAccessLogStream(cas.auditLog.AccessLogEntriesBetween(ctx, f.Between.Start.AsTime(), f.Between.End.AsTime())), nil
		case *requestv1.ListAuditLogEntriesRequest_Since:
			return mkAccessLogStream(cas.auditLog.AccessLogEntriesBetween(ctx, time.Now().Add(-f.Since.AsDuration()), time.Now())), nil
		case *requestv1.ListAuditLogEntriesRequest_Lookup:
			return mkAccessLogStream(cas.auditLog.AccessLogEntryByID(ctx, audit.ID(f.Lookup))), nil
		}
	case requestv1.ListAuditLogEntriesRequest_KIND_DECISION:
		switch f := req.Filter.(type) {
		case *requestv1.ListAuditLogEntriesRequest_Tail:
			return mkDecisionLogStream(cas.auditLog.LastNDecisionLogEntries(ctx, uint(f.Tail))), nil
		case *requestv1.ListAuditLogEntriesRequest_Between:
			return mkDecisionLogStream(cas.auditLog.DecisionLogEntriesBetween(ctx, f.Between.Start.AsTime(), f.Between.End.AsTime())), nil
		case *requestv1.ListAuditLogEntriesRequest_Since:
			return mkDecisionLogStream(cas.auditLog.DecisionLogEntriesBetween(ctx, time.Now().Add(-f.Since.AsDuration()), time.Now())), nil
		case *requestv1.ListAuditLogEntriesRequest_Lookup:
			return mkDecisionLogStream(cas.auditLog.DecisionLogEntryByID(ctx, audit.ID(f.Lookup))), nil
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "Unknown log stream kind")
	}

	return nil, status.Error(codes.InvalidArgument, "Unknown filter")
}

type auditLogStream func() (*responsev1.ListAuditLogEntriesResponse, error)

func mkAccessLogStream(it audit.AccessLogIterator) auditLogStream {
	return func() (*responsev1.ListAuditLogEntriesResponse, error) {
		rec, err := it.Next()
		if err != nil {
			return nil, err
		}

		return &responsev1.ListAuditLogEntriesResponse{
			Entry: &responsev1.ListAuditLogEntriesResponse_AccessLogEntry{
				AccessLogEntry: rec,
			},
		}, nil
	}
}

func mkDecisionLogStream(it audit.DecisionLogIterator) auditLogStream {
	return func() (*responsev1.ListAuditLogEntriesResponse, error) {
		rec, err := it.Next()
		if err != nil {
			return nil, err
		}

		return &responsev1.ListAuditLogEntriesResponse{
			Entry: &responsev1.ListAuditLogEntriesResponse_DecisionLogEntry{
				DecisionLogEntry: rec,
			},
		}, nil
	}
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

	parts := bytes.Split(bytes.TrimSpace(decoded), authSep)
	if len(parts) != 2 { //nolint:gomnd
		return status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if !bytes.Equal(parts[0], []byte(cas.adminUser)) {
		return status.Error(codes.Unauthenticated, "incorrect credentials")
	}

	if err := bcrypt.CompareHashAndPassword(cas.adminPasswdHash, parts[1]); err != nil {
		return status.Error(codes.Unauthenticated, "incorrect credentials")
	}

	return nil
}
