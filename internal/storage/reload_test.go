// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeReloadableStore struct {
	firstReloadStarted chan struct{}
	block              chan struct{}
	starts             []time.Time
	mu                 sync.Mutex
}

func (f *fakeReloadableStore) Reload(_ context.Context) error {
	f.mu.Lock()
	f.starts = append(f.starts, time.Now())
	n := len(f.starts)
	f.mu.Unlock()

	if n == 1 {
		close(f.firstReloadStarted)
		<-f.block
	}

	return nil
}

func (f *fakeReloadableStore) reloadStarts() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]time.Time(nil), f.starts...)
}

func TestReloadCoalescing(t *testing.T) {
	rs := &fakeReloadableStore{
		firstReloadStarted: make(chan struct{}),
		block:              make(chan struct{}),
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- Reload(t.Context(), rs) }()

	select {
	case <-rs.firstReloadStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for the first reload to start")
	}

	// These callers arrive while the first reload is in flight. They must
	// all coalesce into a single follow-up reload.
	const numLateCallers = 3
	lateDone := make(chan error, numLateCallers)
	for range numLateCallers {
		go func() { lateDone <- Reload(t.Context(), rs) }()
	}

	// Give the late callers time to join the follow-up flight before the first reload finishes.
	// If the timeout is too short, this can't produce false positives.
	time.Sleep(200 * time.Millisecond)
	allLateCallersJoinedBy := time.Now()
	close(rs.block)

	require.NoError(t, <-firstDone)
	for range numLateCallers {
		select {
		case err := <-lateDone:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timed out waiting for a late caller to return")
		}
	}

	starts := rs.reloadStarts()
	require.Len(t, starts, 2, "late callers should coalesce into exactly one follow-up reload")
	require.True(t, starts[1].After(allLateCallersJoinedBy), "follow-up reload should have started after all late callers arrived")
}
