// Copyright 2021 Zenauth Ltd.

package audit

import (
	"context"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/internal/genpb/audit/v1"
)

var excludeMetadataKeys = map[string]struct{}{
	"grpc-trace-bin": {},
}

type ExcludeMethod func(string) bool

func NewUnaryInterceptor(log Log, exclude ExcludeMethod) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if exclude(info.FullMethod) {
			return handler(ctx, req)
		}

		ts := time.Now()
		callID, err := NewID()
		if err != nil {
			ctxzap.Extract(ctx).Warn("Failed to generate call ID", zap.Error(err))
			return handler(ctx, req)
		}

		resp, err := handler(NewContextWithCallID(ctx, callID), req)

		if logErr := log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
			entry := &auditv1.AccessLogEntry{
				CallId:     string(callID),
				Timestamp:  timestamppb.New(ts),
				Peer:       PeerFromContext(ctx),
				Method:     info.FullMethod,
				StatusCode: uint32(status.Code(err)),
			}

			md, ok := metadata.FromIncomingContext(ctx)
			if ok {
				entry.Metadata = make(map[string]*auditv1.MetaValues, len(md))
				for key, values := range md {
					if _, ok := excludeMetadataKeys[key]; !ok {
						entry.Metadata[key] = &auditv1.MetaValues{Values: values}
					}
				}
			}

			return entry, nil
		}); logErr != nil {
			ctxzap.Extract(ctx).Warn("Failed to write access log entry", zap.Error(logErr))
		}

		return resp, err
	}
}
