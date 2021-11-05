// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

const (
	ConfKey       = "storage"
	driverConfKey = "storage.driver"
)

var (
	driversMu sync.RWMutex
	drivers   = map[string]Constructor{}
)

// InvalidPolicyError is a custom error to signal that a policy is invalid.
type InvalidPolicyError struct {
	Message string
	Err     error
}

func (ipe InvalidPolicyError) Error() string {
	return fmt.Sprintf("%s: %v", ipe.Message, ipe.Err)
}

func (ipe InvalidPolicyError) Unwrap() error {
	return ipe.Err
}

func NewInvalidPolicyError(err error, msg string, args ...interface{}) InvalidPolicyError {
	return InvalidPolicyError{Message: fmt.Sprintf(msg, args...), Err: err}
}

// Constructor is a constructor function for a storage driver.
type Constructor func(context.Context) (Store, error)

// RegisterDriver registers a storage driver.
func RegisterDriver(name string, cons Constructor) {
	driversMu.Lock()
	defer driversMu.Unlock()

	drivers[name] = cons
}

// New returns a storage driver implementation based on the configured driver.
func New(ctx context.Context) (Store, error) {
	var driver string
	if err := config.Get(driverConfKey, &driver); err != nil {
		return nil, fmt.Errorf("failed to read storage driver name: %w", err)
	}

	driversMu.RLock()
	cons, ok := drivers[driver]
	driversMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown storage driver [%s]", driver)
	}

	return cons(ctx)
}

// Store is the common interface implemented by storage backends.
type Store interface {
	Subscribable
	// Driver is the name of the storage backend implementation.
	Driver() string
	// GetCompilationUnits gets the compilation units for the given module IDs.
	GetCompilationUnits(context.Context, ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	// GetDependents returns the dependents of the given modules.
	GetDependents(context.Context, ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
	// GetPolicies returns the policies recorded in the store.
	GetPolicies(context.Context) ([]*policy.Wrapper, error)
}

// MutableStore is a store that allows mutations.
type MutableStore interface {
	Store
	AddOrUpdate(context.Context, ...policy.Wrapper) error
	Delete(context.Context, ...namer.ModuleID) error
}

// Subscribable is an interface for managing subscriptions to storage events.
type Subscribable interface {
	// Subscribe adds a subscriber to listen for storage notifications.
	Subscribe(Subscriber)
	// Unsubscribe removes a subscriber.
	Unsubscribe(Subscriber)
}

// Subscriber is the interface implemented by storage subscribers.
type Subscriber interface {
	SubscriberID() string
	OnStorageEvent(...Event)
}

// EventKind identifies the kind of storage event such as addition or deletion.
type EventKind int

const (
	EventAddOrUpdatePolicy EventKind = iota
	EventDeletePolicy
	EventNop
)

// Event is an event detected by the storage layer.
type Event struct {
	Kind     EventKind
	PolicyID namer.ModuleID
}

func (evt Event) String() string {
	kind := ""
	switch evt.Kind {
	case EventAddOrUpdatePolicy:
		kind = "ADD/UPDATE"
	case EventDeletePolicy:
		kind = "DELETE"
	case EventNop:
		kind = "NOP"
	default:
		kind = "UNKNOWN"
	}

	return fmt.Sprintf("%s [%s]", kind, evt.PolicyID.String())
}

// NewEvent creates a new storage event.
func NewEvent(kind EventKind, policyID namer.ModuleID) Event {
	return Event{Kind: kind, PolicyID: policyID}
}
