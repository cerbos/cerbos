// Copyright 2021 Zenauth Ltd.

package storage

import (
	"context"
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
)

// Event is an event detected by the storage layer.
type Event struct {
	Kind     EventKind
	PolicyID namer.ModuleID
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

/*
// New creates a new store based on the config.
func New(ctx context.Context) (Store, error) {
	conf, err := getStorageConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read storage config: %w", err)
	}

	switch conf.Driver {
	case disk.DriverName:
		if conf.Disk == nil {
			return nil, errors.New("disk storage configuration not provided")
		}

		if conf.Disk.ReadOnly {
			return disk.NewReadOnlyStore(ctx, conf.Disk)
		}

		return disk.NewReadWriteStore(ctx, conf.Disk)
	case git.DriverName:
		if conf.Git == nil {
			return nil, errors.New("git storage configuration not provided")
		}

		return git.NewStore(ctx, conf.Git)
	default:
		return nil, fmt.Errorf("unknown storage driver: %s", conf.Driver)
	}
}
*/
