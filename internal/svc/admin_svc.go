// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db"
)

var _ svcv1.CerbosAdminServiceServer = (*CerbosAdminService)(nil)

var (
	errAuthRequired = status.Error(codes.Unauthenticated, "authentication required")
	authSep         = []byte(":")
)

// CerbosAdminService implements the Cerbos administration service.
type CerbosAdminService struct {
	sfGroup  singleflight.Group
	store    storage.Store
	auditLog audit.Log
	*svcv1.UnimplementedCerbosAdminServiceServer
	adminUser       string
	adminPasswdHash []byte
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

func (cas *CerbosAdminService) AddPolicy(ctx context.Context, req *requestv1.AddPolicyRequest) (*responsev1.AddPolicyResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	ms, ok := cas.store.(storage.MutableStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store is not mutable")
	}

	policies := make([]policy.Wrapper, len(req.Policies))
	for i, p := range req.Policies {
		policies[i] = policy.Wrap(policy.WithSourceAttributes(p, policy.SourceUpdateTSNow()))
	}

	log := logging.ReqScopeLog(ctx)
	if err := ms.AddOrUpdate(ctx, policies...); err != nil {
		log.Error("Failed to add/update policies", zap.Error(err))
		if errors.Is(err, storage.ErrPolicyIDCollision) {
			return nil, status.Error(codes.FailedPrecondition, "Policy ID conflict")
		}

		invalidPolicyErr := new(storage.InvalidPolicyError)
		if errors.As(err, invalidPolicyErr) {
			return nil, status.Errorf(codes.InvalidArgument, "Invalid policy: %v", invalidPolicyErr.Message)
		}
		return nil, status.Error(codes.Internal, "Failed to add/update policies")
	}

	return &responsev1.AddPolicyResponse{Success: &emptypb.Empty{}}, nil
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
		policies[i] = policy.Wrap(policy.WithSourceAttributes(p, policy.SourceUpdateTSNow()))
	}

	log := logging.ReqScopeLog(ctx)
	if err := ms.AddOrUpdate(ctx, policies...); err != nil {
		log.Error("Failed to add/update policies", zap.Error(err))
		if errors.Is(err, storage.ErrPolicyIDCollision) {
			return nil, status.Error(codes.FailedPrecondition, "Policy ID conflict")
		}

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

	if err := ms.AddOrUpdateSchema(ctx, req.Schemas...); err != nil {
		logging.ReqScopeLog(ctx).Error("Failed to add/update the schema(s)", zap.Error(err))
		var ise storage.InvalidSchemaError
		if ok := errors.As(err, &ise); ok {
			return nil, status.Errorf(codes.InvalidArgument, "Invalid schema in request: %s", ise.Message)
		}

		return nil, status.Errorf(codes.Internal, "Failed to add/update the schema(s)")
	}

	return &responsev1.AddOrUpdateSchemaResponse{}, nil
}

func (cas *CerbosAdminService) InspectPolicies(ctx context.Context, req *requestv1.InspectPoliciesRequest) (*responsev1.InspectPoliciesResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	// Filters are not scalable for non-mutable stores.
	if _, ok := cas.store.(storage.MutableStore); !ok && (req.NameRegexp != "" || req.ScopeRegexp != "" || req.VersionRegexp != "") {
		return nil, status.Error(codes.Unimplemented, "Store does not support regexp filters")
	}

	res, err, _ := cas.sfGroup.Do("inspect_policies", func() (any, error) {
		filterParams := storage.ListPolicyIDsParams{
			IDs:             req.PolicyId,
			NameRegexp:      req.NameRegexp,
			ScopeRegexp:     req.ScopeRegexp,
			VersionRegexp:   req.VersionRegexp,
			IncludeDisabled: req.IncludeDisabled,
		}

		res, err := cas.store.InspectPolicies(ctx, filterParams)
		if err != nil {
			logging.ReqScopeLog(ctx).Error("Could not inspect policies", zap.Error(err))
			return nil, status.Error(codes.Internal, "could not inspect policies")
		}

		return res, nil
	})
	if err != nil {
		return nil, err
	}

	results, ok := res.(map[string]*responsev1.InspectPoliciesResponse_Result)
	if !ok {
		return nil, fmt.Errorf("failed to type assert during inspect policies")
	}

	return &responsev1.InspectPoliciesResponse{Results: results}, nil
}

func (cas *CerbosAdminService) ListPolicies(ctx context.Context, req *requestv1.ListPoliciesRequest) (*responsev1.ListPoliciesResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	// We've historically supported ListPolicies on non-mutable stores, but later introduced filters are not scalable.
	// Therefore, if any of the filters in question are passed and the store is not mutable, we reject the request.
	if _, ok := cas.store.(storage.MutableStore); !ok && (req.NameRegexp != "" || req.ScopeRegexp != "" || req.VersionRegexp != "") {
		return nil, status.Error(codes.Unimplemented, "Store does not support regexp filters")
	}

	filterParams := storage.ListPolicyIDsParams{
		NameRegexp:      req.NameRegexp,
		ScopeRegexp:     req.ScopeRegexp,
		VersionRegexp:   req.VersionRegexp,
		IncludeDisabled: req.IncludeDisabled,
		IDs:             req.PolicyId,
	}

	policyIDs, err := cas.store.ListPolicyIDs(context.Background(), filterParams)
	if err != nil {
		logging.ReqScopeLog(ctx).Error("Could not get policy ids", zap.Error(err))
		return nil, status.Error(codes.Internal, "could not get policy ids")
	}

	sort.Strings(policyIDs)
	return &responsev1.ListPoliciesResponse{
		PolicyIds: policyIDs,
	}, nil
}

func (cas *CerbosAdminService) GetPolicy(ctx context.Context, req *requestv1.GetPolicyRequest) (*responsev1.GetPolicyResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	ss, ok := cas.store.(storage.SourceStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store does not contain policy sources")
	}

	log := logging.ReqScopeLog(ctx)
	wrappers, err := ss.LoadPolicy(ctx, req.Id...)
	if err != nil {
		log.Error("Could not get policy", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "could not get policy")
	}

	policies := make([]*policyv1.Policy, len(wrappers))
	for i, wrapper := range wrappers {
		policies[i] = wrapper.Policy
	}

	return &responsev1.GetPolicyResponse{
		Policies: policies,
	}, nil
}

func (cas *CerbosAdminService) DisablePolicy(ctx context.Context, req *requestv1.DisablePolicyRequest) (*responsev1.DisablePolicyResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	ms, ok := cas.store.(storage.MutableStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store is not mutable")
	}

	disabledPolicies, err := ms.Disable(ctx, req.Id...)
	if err != nil {
		logging.ReqScopeLog(ctx).Error("Failed to disable policies", zap.Error(err))
		if errors.As(err, &db.ErrBreaksScopeChain{}) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, "Failed to disable policies")
	}

	return &responsev1.DisablePolicyResponse{
		DisabledPolicies: disabledPolicies,
	}, nil
}

func (cas *CerbosAdminService) EnablePolicy(ctx context.Context, req *requestv1.EnablePolicyRequest) (*responsev1.EnablePolicyResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	ms, ok := cas.store.(storage.MutableStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store is not mutable")
	}

	enabledPolicies, err := ms.Enable(ctx, req.Id...)
	if err != nil {
		logging.ReqScopeLog(ctx).Error("Failed to enable policies", zap.Error(err))
		return nil, status.Error(codes.Internal, "Failed to enable policies")
	}

	return &responsev1.EnablePolicyResponse{
		EnabledPolicies: enabledPolicies,
	}, nil
}

func (cas *CerbosAdminService) ListSchemas(ctx context.Context, _ *requestv1.ListSchemasRequest) (*responsev1.ListSchemasResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	schemaIDs, err := cas.store.ListSchemaIDs(ctx)
	if err != nil {
		logging.ReqScopeLog(ctx).Error("Failed to list schema ids", zap.Error(err))
		return nil, status.Error(codes.NotFound, "failed to list schema ids")
	}

	sort.Strings(schemaIDs)
	return &responsev1.ListSchemasResponse{
		SchemaIds: schemaIDs,
	}, nil
}

func (cas *CerbosAdminService) GetSchema(ctx context.Context, req *requestv1.GetSchemaRequest) (*responsev1.GetSchemaResponse, error) {
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	if cas.store == nil {
		return nil, status.Error(codes.NotFound, "store is not configured")
	}

	log := logging.ReqScopeLog(ctx)

	schemas := make([]*schemav1.Schema, 0, len(req.Id))
	for _, id := range req.Id {
		sch, err := cas.store.LoadSchema(context.Background(), id)
		if err != nil {
			log.Error(fmt.Sprintf("Could not get the schema with id %s", id), zap.Error(err))
			return nil, status.Errorf(codes.Internal, "could not get the schema with id %s", id)
		}

		schBytes, err := io.ReadAll(sch)
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

	deletedSchemas, err := ms.DeleteSchema(ctx, req.Id...)
	if err != nil {
		logging.ReqScopeLog(ctx).Error("Failed to delete the schema(s)", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Failed to delete the schema(s)")
	}

	return &responsev1.DeleteSchemaResponse{DeletedSchemas: deletedSchemas}, nil
}

func (cas *CerbosAdminService) ReloadStore(ctx context.Context, req *requestv1.ReloadStoreRequest) (*responsev1.ReloadStoreResponse, error) {
	log := logging.ReqScopeLog(ctx)
	if err := cas.checkCredentials(ctx); err != nil {
		return nil, err
	}

	rs, ok := cas.store.(storage.Reloadable)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Configured store is not reloadable")
	}

	reload := func(ctx context.Context) error {
		if err := storage.Reload(ctx, rs); err != nil {
			log.Error("failed to reload store", zap.Error(err))
			return err
		}
		return nil
	}

	if !req.Wait {
		//nolint:errcheck
		go reload(logging.ToContext(context.Background(), log))
		return &responsev1.ReloadStoreResponse{}, nil
	}

	if err := reload(ctx); err != nil {
		return nil, status.Error(codes.Internal, "failed to reload store")
	}

	return &responsev1.ReloadStoreResponse{}, nil
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

			logging.ReqScopeLog(ctx).Error("Error from log iterator", zap.Error(err))
			return status.Error(codes.Internal, "Iterator failure")
		}

		if err := stream.Send(rec); err != nil {
			logging.ReqScopeLog(ctx).Error("Error writing to stream", zap.Error(err))
			return err
		}
	}
}

func (cas *CerbosAdminService) getAuditLogStream(ctx context.Context, req *requestv1.ListAuditLogEntriesRequest) (auditLogStream, error) {
	if !cas.auditLog.Enabled() {
		return nil, status.Error(codes.Unimplemented, "Audit logs are not enabled")
	}

	if cas.auditLog.Backend() == "" {
		return nil, status.Error(codes.Unimplemented, "No audit log backend is configured")
	}

	queryableLog, ok := cas.auditLog.(audit.QueryableLog)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Audit log backend does not support querying")
	}

	switch req.Kind {
	case requestv1.ListAuditLogEntriesRequest_KIND_ACCESS:
		switch f := req.Filter.(type) {
		case *requestv1.ListAuditLogEntriesRequest_Tail:
			return mkAccessLogStream(queryableLog.LastNAccessLogEntries(ctx, uint(f.Tail))), nil
		case *requestv1.ListAuditLogEntriesRequest_Between:
			return mkAccessLogStream(queryableLog.AccessLogEntriesBetween(ctx, f.Between.Start.AsTime(), f.Between.End.AsTime())), nil
		case *requestv1.ListAuditLogEntriesRequest_Since:
			return mkAccessLogStream(queryableLog.AccessLogEntriesBetween(ctx, time.Now().Add(-f.Since.AsDuration()), time.Now())), nil
		case *requestv1.ListAuditLogEntriesRequest_Lookup:
			return mkAccessLogStream(queryableLog.AccessLogEntryByID(ctx, audit.ID(f.Lookup))), nil
		}
	case requestv1.ListAuditLogEntriesRequest_KIND_DECISION:
		switch f := req.Filter.(type) {
		case *requestv1.ListAuditLogEntriesRequest_Tail:
			return mkDecisionLogStream(queryableLog.LastNDecisionLogEntries(ctx, uint(f.Tail))), nil
		case *requestv1.ListAuditLogEntriesRequest_Between:
			return mkDecisionLogStream(queryableLog.DecisionLogEntriesBetween(ctx, f.Between.Start.AsTime(), f.Between.End.AsTime())), nil
		case *requestv1.ListAuditLogEntriesRequest_Since:
			return mkDecisionLogStream(queryableLog.DecisionLogEntriesBetween(ctx, time.Now().Add(-f.Since.AsDuration()), time.Now())), nil
		case *requestv1.ListAuditLogEntriesRequest_Lookup:
			return mkDecisionLogStream(queryableLog.DecisionLogEntryByID(ctx, audit.ID(f.Lookup))), nil
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
	if len(parts) != 2 { //nolint:mnd
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
