// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package storage_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage"
)

type ctxCaller struct{}

var ctxCallerKey = &ctxCaller{}

type fakeReloadableStore struct {
	block   chan struct{}
	callers chan any
}

func (f *fakeReloadableStore) Reload(ctx context.Context) error {
	caller := ctx.Value(ctxCallerKey)
	f.callers <- caller

	<-f.block
	time.Sleep(100 * time.Millisecond)

	return nil
}

func TestReloadCoalescing(t *testing.T) {
	rs := &fakeReloadableStore{
		block:   make(chan struct{}),
		callers: make(chan any, 8),
	}

	var wg sync.WaitGroup
	// First request that enters the singleflight group and is "blocked"
	wg.Go(func() {
		ctx := context.WithValue(context.Background(), ctxCallerKey, "A")
		_ = storage.Reload(ctx, rs)
	})

	// Wait for "A" to start
	first := <-rs.callers
	require.Equal(t, "A", first)

	// Launch other requests that arrive after A and concurrently.
	for _, c := range []string{"B", "C", "D", "E", "F"} {
		wg.Go(func() {
			ctx := context.WithValue(context.Background(), ctxCallerKey, c)
			_ = storage.Reload(ctx, rs)
		})
	}

	// Finish A's call
	rs.block <- struct{}{}

	// No more blocking. Every call takes 100ms.
	close(rs.block)

	wg.Wait()
	close(rs.callers)
	callers := make([]string, 0, len(rs.callers))
	for c := range rs.callers {
		callers = append(callers, c.(string))
	}

	t.Logf("%++v", append([]string{first.(string)}, callers...))
	require.Len(t, callers, 1)
}
