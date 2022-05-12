// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"strings"
	"time"

	telemetryv1 "github.com/cerbos/cerbos/api/genpb/cerbos/telemetry/v1"
	"github.com/cerbos/cerbos/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
)

type methodInfo struct {
	name      string
	userAgent string
}

type Interceptor struct {
	infoChan    chan methodInfo
	methodTally map[string]uint64
	uaTally     map[string]uint64
	totalReq    uint64
}

func NewInterceptor(ctx context.Context) *Interceptor {
	i := &Interceptor{
		infoChan:    make(chan methodInfo, 64),
		methodTally: make(map[string]uint64),
		uaTally:     make(map[string]uint64),
	}

	go i.doTally(ctx)

	return i
}

func (i *Interceptor) doTally(ctx context.Context) {
	conf := &Conf{}
	_ = config.GetSection(conf)

	ticker := time.NewTicker(conf.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			i.report()
			return
		case <-ticker.C:
			i.report()
		case m := <-i.infoChan:
			i.methodTally[m.name]++
			i.uaTally[m.userAgent]++
			i.totalReq++
		}
	}
}

func (i *Interceptor) report() {
	Report(&telemetryv1.Event{
		Data: &telemetryv1.Event_ApiActivity_{
			ApiActivity: &telemetryv1.Event_ApiActivity{
				Version:     "1.0.0",
				Uptime:      durationpb.New(time.Since(startTime)),
				MethodCalls: copyMap(i.methodTally),
				UserAgents:  copyMap(i.uaTally),
			},
		},
	})
}

func copyMap(m map[string]uint64) map[string]uint64 {
	c := make(map[string]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}

	return c
}

func (i *Interceptor) UnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !strings.HasPrefix(info.FullMethod, "/grpc.") {
		mInfo := methodInfo{name: info.FullMethod, userAgent: "unknown"}

		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if v := md.Get("user-agent"); len(v) > 0 {
				mInfo.userAgent = v[0]
			}
		}

		select {
		case i.infoChan <- mInfo:
		default:
		}
	}

	return handler(ctx, req)
}
