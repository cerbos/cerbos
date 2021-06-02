// Copyright 2021 Zenauth Ltd.

package storage

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

const eventBufferSize = 16

type SubscriptionManager struct {
	once        sync.Once
	eventChan   chan Event
	mu          sync.RWMutex
	subscribers map[string]Subscriber
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
		// TODO (cell) Handle stragglers
		sub.OnStorageEvent(evt)
	}
}

// Notify sends the events to all subscribers.
func (sm *SubscriptionManager) NotifySubscribers(events ...Event) {
	for _, evt := range events {
		if evt.Kind == EventNop {
			continue
		}

		select {
		case sm.eventChan <- evt:
		}
	}
}

func (sm *SubscriptionManager) Subscribe(s Subscriber) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.subscribers[s.SubscriberID()] = s
}

func (sm *SubscriptionManager) Unsubscribe(s Subscriber) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.subscribers, s.SubscriberID())
}

func (sm *SubscriptionManager) shutdown() {
	sm.once.Do(func() { close(sm.eventChan) })
}

// TestSubscription is a helper to test subscriptions.
func TestSubscription(store Store) func(*testing.T, ...Event) {
	sub := &subscriber{}
	store.Subscribe(sub)

	return func(t *testing.T, wantEvents ...Event) {
		t.Helper()

		runtime.Gosched()

		haveEvents := sub.Events()
		store.Unsubscribe(sub)

		require.ElementsMatch(t, wantEvents, haveEvents)
	}
}

type subscriber struct {
	mu     sync.RWMutex
	events []Event
}

func (s *subscriber) SubscriberID() string {
	return "test"
}

func (s *subscriber) OnStorageEvent(evt ...Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, evt...)
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
