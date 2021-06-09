// Copyright 2021 Zenauth Ltd.

package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

var (
	driversMu sync.RWMutex
	drivers   = map[string]Constructor{}
)

var ErrNoMatchingPolicy = errors.New("no matching policy")

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
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to read storage configuration: %w", err)
	}

	driversMu.RLock()
	cons, ok := drivers[conf.Driver]
	driversMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown storage driver [%s]", conf.Driver)
	}

	return cons(ctx)
}

// Store is the common interface implemented by storage backends.
type Store interface {
	// Driver is the name of the storage backend implementation.
	Driver() string
	// Subscribe adds a subscriber to listen for storage notifications.
	Subscribe(Subscriber)
	// Unsubscribe removes a subscriber.
	Unsubscribe(Subscriber)
	// GetCompilationUnits gets the compilation units for the given module IDs.
	GetCompilationUnits(context.Context, ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	// GetDependents returns the dependents of the given modules.
	GetDependents(context.Context, ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
}

// MutableStore is a store that allows mutations.
type MutableStore interface {
	Store
	AddOrUpdate(context.Context, ...policy.Wrapper) error
	Delete(context.Context, ...namer.ModuleID) error
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

// Subscriber is the interface implemented by storage subscribers.
type Subscriber interface {
	SubscriberID() string
	OnStorageEvent(...Event)
}
