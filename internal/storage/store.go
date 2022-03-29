// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
	"io"
	"sync"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

var (
	driversMu sync.RWMutex
	drivers   = map[string]Constructor{}
)

// InvalidPolicyError is a custom error to signal that a policy is invalid.
type InvalidPolicyError struct {
	Err     error
	Message string
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

// InvalidSchemaError is a custom error to signal that a schema is invalid.
type InvalidSchemaError struct {
	Err     error
	Message string
}

func (ise InvalidSchemaError) Error() string {
	return fmt.Sprintf("%s: %v", ise.Message, ise.Err)
}

func (ise InvalidSchemaError) Unwrap() error {
	return ise.Err
}

func NewInvalidSchemaError(err error, msg string, args ...interface{}) InvalidSchemaError {
	return InvalidSchemaError{Message: fmt.Sprintf(msg, args...), Err: err}
}

// Constructor is a constructor function for a storage driver.
type Constructor func(context.Context, *config.Wrapper) (Store, error)

// RegisterDriver registers a storage driver.
func RegisterDriver(name string, cons Constructor) {
	driversMu.Lock()
	defer driversMu.Unlock()

	drivers[name] = cons
}

// New returns a storage driver implementation based on the configured driver.
func New(ctx context.Context) (Store, error) {
	return NewFromConf(ctx, config.Global())
}

// NewFromConf returns a storage driver implementation based on the provided configuration.
func NewFromConf(ctx context.Context, confWrapper *config.Wrapper) (Store, error) {
	conf := new(Conf)
	if err := confWrapper.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to get storage driver configuration: %w", err)
	}

	driversMu.RLock()
	cons, ok := drivers[conf.Driver]
	driversMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown storage driver [%s]", conf.Driver)
	}

	return cons(ctx, confWrapper)
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
	// ListPolicyIDs returns the policy IDs in the store
	ListPolicyIDs(context.Context) ([]string, error)
	// ListSchemaIDs returns the schema ids in the store
	ListSchemaIDs(context.Context) ([]string, error)
	// LoadSchema loads the given schema from the store.
	LoadSchema(context.Context, string) (io.ReadCloser, error)
	// LoadPolicy loads the given policy from the store
	LoadPolicy(context.Context, ...string) ([]*policy.Wrapper, error)
}

// MutableStore is a store that allows mutations.
type MutableStore interface {
	Store
	AddOrUpdate(context.Context, ...policy.Wrapper) error
	AddOrUpdateSchema(context.Context, ...*schemav1.Schema) error
	DeleteSchema(context.Context, ...string) error
	Delete(context.Context, ...namer.ModuleID) error
}

// ReloadableStore is a store that allows reloading (blob, disk, git).
type ReloadableStore interface {
	Store
	Reload(context.Context) error
}

// Instrumented stores expose repository stats.
type Instrumented interface {
	RepoStats(context.Context) RepoStats
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
	EventAddOrUpdateSchema
	EventDeleteSchema
	EventNop
)

// Event is an event detected by the storage layer.
type Event struct {
	SchemaFile string
	Kind       EventKind
	PolicyID   namer.ModuleID
}

func (evt Event) String() string {
	var kind string
	id := evt.PolicyID.String()
	switch evt.Kind {
	case EventAddOrUpdatePolicy:
		kind = "ADD/UPDATE"
	case EventDeletePolicy:
		kind = "DELETE"
	case EventAddOrUpdateSchema:
		kind = "ADD/UPDATE SCHEMA"
		id = evt.SchemaFile
	case EventDeleteSchema:
		kind = "DELETE SCHEMA"
		id = evt.SchemaFile
	case EventNop:
		kind = "NOP"
	default:
		kind = "UNKNOWN"
	}

	return fmt.Sprintf("%s [%s]", kind, id)
}

// NewPolicyEvent creates a new storage event for a policy.
func NewPolicyEvent(kind EventKind, policyID namer.ModuleID) Event {
	return Event{Kind: kind, PolicyID: policyID}
}

// NewSchemaEvent creates a new storage event for a schema.
func NewSchemaEvent(kind EventKind, schemaFile string) Event {
	return Event{Kind: kind, SchemaFile: schemaFile}
}

type RepoStats struct {
	PolicyCount       map[policy.Kind]int
	AvgRuleCount      map[policy.Kind]float64
	AvgConditionCount map[policy.Kind]float64
	SchemaCount       int
}
