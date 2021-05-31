// Copyright 2021 Zenauth Ltd.

package storage

import "sync"

const eventBufferSize = 16

type SubscriptionManager struct {
	once        sync.Once
	eventChan   chan Event
	mu          sync.RWMutex
	subscribers map[string]Subscriber
}

func NewSubscriptionManager() *SubscriptionManager {
	sm := &SubscriptionManager{
		eventChan:   make(chan Event, eventBufferSize),
		subscribers: make(map[string]Subscriber),
	}

	go sm.handleEvents()

	return sm
}

func (sm *SubscriptionManager) handleEvents() {
	for evt := range sm.eventChan {
		sm.distributeEvent(evt)
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
		sm.eventChan <- evt
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

func (sm *SubscriptionManager) Shutdown() error {
	sm.once.Do(func() { close(sm.eventChan) })
	return nil
}
