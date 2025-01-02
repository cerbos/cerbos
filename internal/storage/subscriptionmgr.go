// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const eventBufferSize = 32

type SubscriptionManager struct {
	eventChan   chan Event
	subscribers map[string]Subscriber
	mu          sync.RWMutex
	once        sync.Once
}

func NewSubscriptionManager(ctx context.Context) *SubscriptionManager {
	sm := &SubscriptionManager{
		eventChan:   make(chan Event, eventBufferSize),
		subscribers: make(map[string]Subscriber),
	}

	go sm.handleEvents(ctx)

	return sm
}

func (sm *SubscriptionManager) handleEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			sm.shutdown()
			return
		case evt, ok := <-sm.eventChan:
			if !ok {
				return
			}
			sm.distributeEvent(evt)
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

// Notify sends the events to all subscribers.
func (sm *SubscriptionManager) NotifySubscribers(events ...Event) {
	for _, evt := range events {
		if evt.Kind == EventNop {
			continue
		}

		// TODO(cell) drop event if not published within a reasonable time period.
		sm.eventChan <- evt
	}
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

func (sm *SubscriptionManager) shutdown() {
	sm.once.Do(func() { close(sm.eventChan) })
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
		require.ElementsMatch(t, wantEvents, haveEvents)
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
