// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
)

type (
	ExcludeMethod     func(string) bool
	IncludeKeysMethod func(string) bool
)

func NewUnaryInterceptor(log Log, exclude ExcludeMethod) (grpc.UnaryServerInterceptor, error) {
	mdExtractor, err := NewMetadataExtractor()
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if exclude(info.FullMethod) {
			return handler(ctx, req)
		}

		ts := time.Now()
		callID, err := NewID()
		if err != nil {
			logging.FromContext(ctx).Warn("Failed to generate call ID", zap.Error(err))
			return handler(ctx, req)
		}

		resp, err := handler(NewContextWithCallID(ctx, callID), req)

		if logErr := log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
			ctx, span := tracing.StartSpan(ctx, "audit.WriteAccessLog")
			defer span.End()

			return &auditv1.AccessLogEntry{
				CallId:     string(callID),
				Timestamp:  timestamppb.New(ts),
				Peer:       PeerFromContext(ctx),
				Method:     info.FullMethod,
				StatusCode: uint32(status.Code(err)),
				Metadata:   mdExtractor(ctx),
			}, nil
		}); logErr != nil {
			logging.FromContext(ctx).Warn("Failed to write access log entry", zap.Error(logErr))
		}

		setCerbosCallID(string(callID), resp)
		return resp, err
	}, nil
}

type cerbosAPIResponse interface {
	proto.Message
	GetCerbosCallId() string
}

func setCerbosCallID(callID string, resp any) {
	if resp == nil {
		return
	}

	// don't panic in case there's nil pointer error
	defer func() {
		_ = recover()
	}()

	if r, ok := resp.(cerbosAPIResponse); ok {
		fd := r.ProtoReflect().Descriptor().Fields().ByTextName("cerbos_call_id")
		if fd != nil {
			r.ProtoReflect().Set(fd, protoreflect.ValueOf(callID))
		}
	}
}
