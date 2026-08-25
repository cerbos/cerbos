// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package storage

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

const eventBufferSize = 32

var errSubscriptionManagerStopped = errors.New("subscription manager stopped")

type eventBatch struct {
	done   chan struct{}
	events []Event
}

type SubscriptionManager struct {
	eventChan   chan eventBatch // never closed
	subscribers map[string]Subscriber
	stopped     <-chan struct{} // closed when the lifecycle ctx is cancelled
	mu          sync.RWMutex
}

func NewSubscriptionManager(ctx context.Context) *SubscriptionManager {
	sm := &SubscriptionManager{
		eventChan:   make(chan eventBatch, eventBufferSize),
		subscribers: make(map[string]Subscriber),
		stopped:     ctx.Done(),
	}

	go sm.handleEvents()

	return sm
}

func (sm *SubscriptionManager) handleEvents() {
	for {
		select {
		case <-sm.stopped:
			return
		case batch := <-sm.eventChan:
			for _, evt := range batch.events {
				sm.distributeEvent(evt)
			}
			if batch.done != nil {
				close(batch.done)
			}
		}
	}
}

func (sm *SubscriptionManager) distributeEvent(evt Event) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, sub := range sm.subscribers {
		// TODO(cell) Use work pool to notify multiple subscribers in parallel.
		sub.OnStorageEvent(evt)
	}
}

// NotifySubscribers sends the events to all subscribers without waiting for them to be processed.
func (sm *SubscriptionManager) NotifySubscribers(events ...Event) {
	if sm == nil {
		return
	}

	for _, evt := range events {
		if evt.Kind == EventNop {
			continue
		}

		// Blocking on a full buffer. Dropping events could compromise consistency with a storage
		// since updates are deltas unless ReloadEvent is enqueued instead.
		select {
		case sm.eventChan <- eventBatch{events: []Event{evt}}:
		case <-sm.stopped:
			return
		}
	}
}

// NotifySubscribersAndWait sends the events to all subscribers and blocks until every
// subscriber has processed them. Events queued ahead of this batch are processed first.
func (sm *SubscriptionManager) NotifySubscribersAndWait(ctx context.Context, events ...Event) error {
	if sm == nil {
		return nil
	}

	events = withoutNopEvents(events)
	if len(events) == 0 {
		return nil
	}

	done := make(chan struct{})
	select {
	case sm.eventChan <- eventBatch{events: events, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	case <-sm.stopped:
		return errSubscriptionManagerStopped
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-sm.stopped:
		return errSubscriptionManagerStopped
	}
}

func withoutNopEvents(events []Event) []Event {
	hasNop := false
	for _, evt := range events {
		if evt.Kind == EventNop {
			hasNop = true
			break
		}
	}
	if !hasNop {
		return events
	}

	filtered := make([]Event, 0, len(events))
	for _, evt := range events {
		if evt.Kind != EventNop {
			filtered = append(filtered, evt)
		}
	}

	return filtered
}

func (sm *SubscriptionManager) Subscribe(s Subscriber) {
	if sm == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.subscribers[s.SubscriberID()] = s
}

func (sm *SubscriptionManager) Unsubscribe(s Subscriber) {
	if sm == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.subscribers, s.SubscriberID())
}

// TestSubscription is a helper to test subscriptions.
func TestSubscription(s Subscribable) func(*testing.T, time.Duration, ...Event) {
	stream := make(chan Event, eventBufferSize)

	sub := &subscriber{stream: stream}
	s.Subscribe(sub)

	return func(t *testing.T, timeout time.Duration, wantEvents ...Event) {
		t.Helper()

		timer := time.NewTimer(timeout)
		t.Cleanup(func() {
			close(stream)
			timer.Stop()
		})

		var haveEvents []Event
		for len(haveEvents) < len(wantEvents) {
			select {
			case evt := <-stream:
				haveEvents = append(haveEvents, evt)
			case <-timer.C:
				t.Errorf("Timeout: expected %d events but only received %d", len(wantEvents), len(haveEvents))
			}
		}

		s.Unsubscribe(sub)
		require.Empty(
			t,
			cmp.Diff(
				wantEvents,
				haveEvents,
				// sort top-level Events by PolicyID.hash, then by SchemaFile for schema events
				cmpopts.SortSlices(func(a, b Event) bool {
					aHash := reflect.ValueOf(a.PolicyID).FieldByName("hash").Uint()
					bHash := reflect.ValueOf(b.PolicyID).FieldByName("hash").Uint()
					if aHash != bHash {
						return aHash < bHash
					}
					// For events with same PolicyID hash (like schema events), sort by SchemaFile
					return a.SchemaFile < b.SchemaFile
				}),
				// sort Dependents by hash
				cmpopts.SortSlices(func(a, b namer.ModuleID) bool {
					return reflect.ValueOf(a).FieldByName("hash").Uint() <
						reflect.ValueOf(b).FieldByName("hash").Uint()
				}),
				// allow comparing ModuleID despite its unexported field
				cmpopts.EquateComparable(namer.ModuleID{}),
			),
			"events mismatch (-want +got)",
		)
	}
}

type subscriber struct {
	stream chan Event
	events []Event
	mu     sync.RWMutex
}

func (s *subscriber) SubscriberID() string {
	return "test"
}

func (s *subscriber) OnStorageEvent(evt ...Event) {
	s.mu.Lock()
	s.events = append(s.events, evt...)
	s.mu.Unlock()

	for _, e := range evt {
		select {
		case s.stream <- e:
		default:
		}
	}
}

func (s *subscriber) Events() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := make([]Event, len(s.events))
	copy(events, s.events)

	return events
}

func (s *subscriber) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = nil
}
