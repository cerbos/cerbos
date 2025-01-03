// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	telemetryv1 "github.com/cerbos/cerbos/api/genpb/cerbos/telemetry/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
)

const collectorBufferSize = 64

var totalReqCount uint64

type Interceptors interface {
	UnaryServerInterceptor() grpc.UnaryServerInterceptor
	StreamServerInterceptor() grpc.StreamServerInterceptor
}

type nopInterceptors struct{}

func (nopInterceptors) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(ctx, req)
	}
}

func (nopInterceptors) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}
}

type methodInfo struct {
	name      string
	userAgent string
}

type statsInterceptors struct {
	reporter    Reporter
	collector   chan methodInfo
	methodTally map[string]uint64
	uaTally     map[string]uint64
}

func newStatsInterceptors(reporter Reporter, interval time.Duration, shutdown <-chan struct{}) *statsInterceptors {
	i := &statsInterceptors{
		reporter:    reporter,
		collector:   make(chan methodInfo, collectorBufferSize),
		methodTally: make(map[string]uint64),
		uaTally:     make(map[string]uint64),
	}

	go i.doTally(interval, shutdown)

	return i
}

func (i *statsInterceptors) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		i.collectStats(ctx, info.FullMethod)
		return handler(ctx, req)
	}
}

func (i *statsInterceptors) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		i.collectStats(ss.Context(), info.FullMethod)
		return handler(srv, ss)
	}
}

func (i *statsInterceptors) collectStats(ctx context.Context, method string) {
	if strings.HasPrefix(method, "/grpc.") {
		return
	}

	mInfo := methodInfo{name: method, userAgent: "unknown"}

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if v := md.Get("grpcgateway-user-agent"); len(v) > 0 {
			mInfo.userAgent = v[0]
		} else if v := md.Get("user-agent"); len(v) > 0 {
			mInfo.userAgent = v[0]
		}
	}

	select {
	case i.collector <- mInfo:
	default:
	}
}

func (i *statsInterceptors) doTally(interval time.Duration, shutdown <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			i.report()
		case m := <-i.collector:
			i.methodTally[m.name]++
			i.uaTally[m.userAgent]++
			atomic.AddUint64(&totalReqCount, 1)
		}
	}
}

func (i *statsInterceptors) report() {
	i.reporter.Report(&telemetryv1.Event{
		Data: &telemetryv1.Event_ApiActivity_{
			ApiActivity: &telemetryv1.Event_ApiActivity{
				Version:     "1.0.0",
				Uptime:      durationpb.New(time.Since(startTime)),
				MethodCalls: toCountStats(i.methodTally),
				UserAgents:  toCountStats(i.uaTally),
			},
		},
	})
}

func toCountStats(m map[string]uint64) []*telemetryv1.Event_CountStat {
	c := make([]*telemetryv1.Event_CountStat, len(m))
	i := 0

	for k, v := range m {
		c[i] = &telemetryv1.Event_CountStat{Key: k, Count: v}
		i++
	}

	return c
}
