// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	telemetryv1 "github.com/cerbos/cerbos/api/genpb/cerbos/telemetry/v1"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/metadata"
)

func TestMiddleware(t *testing.T) {
	mock := &mockReporter{}
	shutdown := make(chan struct{})
	middleware := newStatsInterceptors(mock, 1*time.Millisecond, shutdown)

	ctx, cancelFunc := context.WithCancel(t.Context())
	t.Cleanup(cancelFunc)

	g, _ := errgroup.WithContext(ctx)

	for range 100 {
		g.Go(func() error {
			methods := []string{
				"/cerbos.svc.v1.CerbosService/CheckResources",
				"/cerbos.svc.v1.CerbosService/CheckResourceBatch",
				"/cerbos.svc.v1.CerbosAdminService/ListPolicies",
				"/grpc.health.svc/health",
			}

			md := metadata.New(map[string]string{"user-agent": "grpc/v1.14.6"})
			ctx := metadata.NewIncomingContext(t.Context(), md)

			for j := range 10_000 {
				idx := j % len(methods)
				middleware.collectStats(ctx, methods[idx])
			}

			return nil
		})
	}

	require.NoError(t, g.Wait())

	time.Sleep(3 * time.Millisecond)
	close(shutdown)

	mock.mu.RLock()
	total := mock.count
	methodCalls := toMap(mock.lastEvent.MethodCalls)
	userAgents := toMap(mock.lastEvent.UserAgents)
	mock.mu.RUnlock()

	require.True(t, total > 0)
	require.Contains(t, methodCalls, "/cerbos.svc.v1.CerbosService/CheckResources")
	require.True(t, methodCalls["/cerbos.svc.v1.CerbosService/CheckResources"] > 0)
	require.NotContains(t, methodCalls, "/grpc.health.svc/health")
	require.True(t, userAgents["grpc/v1.14.6"] > 0)
}

func toMap(c []*telemetryv1.Event_CountStat) map[string]uint64 {
	m := make(map[string]uint64, len(c))
	for _, v := range c {
		m[v.Key] = v.Count
	}

	return m
}

type mockReporter struct {
	mu        sync.RWMutex
	count     uint64
	lastEvent *telemetryv1.Event_ApiActivity
}

func (m *mockReporter) Report(event *telemetryv1.Event) bool {
	apiActivity := event.GetApiActivity()
	if apiActivity == nil {
		panic(fmt.Errorf("unexpected event: %T", event.Data))
	}

	m.mu.Lock()
	m.count++
	m.lastEvent = apiActivity
	m.mu.Unlock()

	return true
}

func (m *mockReporter) Intercept() Interceptors {
	return nil
}

func (m *mockReporter) Stop() error {
	return nil
}
