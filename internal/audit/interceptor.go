// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
)

type (
	ExcludeMethod     func(string) bool
	IncludeKeysMethod func(string) bool
)

func NewUnaryInterceptor(log Log, exclude ExcludeMethod) (grpc.UnaryServerInterceptor, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read audit configuration: %w", err)
	}

	includeKeys := mkIncludeKeysMethod(conf.ExcludeMetadataKeys, conf.IncludeMetadataKeys)

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
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

			if !(len(conf.ExcludeMetadataKeys) == 0 && len(conf.IncludeMetadataKeys) == 0) {
				md, ok := metadata.FromIncomingContext(ctx)
				if ok {
					entry.Metadata = make(map[string]*auditv1.MetaValues, len(md))
					for key, values := range md {
						if includeKeys(key) {
							entry.Metadata[key] = &auditv1.MetaValues{Values: values}
						}
					}
				}
			}

			return entry, nil
		}); logErr != nil {
			ctxzap.Extract(ctx).Warn("Failed to write access log entry", zap.Error(logErr))
		}

		return resp, err
	}, nil
}

func mkIncludeKeysMethod(excludedMetadataKeys, includedMetadataKeys []string) IncludeKeysMethod {
	exclude := sliceToLookupMap(excludedMetadataKeys)
	include := sliceToLookupMap(includedMetadataKeys)
	return func(key string) bool {
		_, existsInExcludedKeys := exclude[key]
		_, existsInIncludedKeys := include[key]

		if !existsInExcludedKeys && existsInIncludedKeys {
			return true
		}

		return false
	}
}

func sliceToLookupMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, k := range slice {
		m[k] = struct{}{}
	}

	return m
}
