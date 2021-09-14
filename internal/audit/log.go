// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/config"
)

var (
	ErrIteratorClosed = errors.New("iterator closed")

	backendsMu sync.RWMutex
	backends   = map[string]Constructor{}
)

type Log interface {
	WriteAccessLogEntry(context.Context, AccessLogEntryMaker) error
	WriteDecisionLogEntry(context.Context, DecisionLogEntryMaker) error
	LastNAccessLogEntries(context.Context, uint) AccessLogIterator
	LastNDecisionLogEntries(context.Context, uint) DecisionLogIterator
	AccessLogEntriesBetween(context.Context, time.Time, time.Time) AccessLogIterator
	DecisionLogEntriesBetween(context.Context, time.Time, time.Time) DecisionLogIterator
	AccessLogEntryByID(context.Context, ID) AccessLogIterator
	DecisionLogEntryByID(context.Context, ID) DecisionLogIterator
	Close()
}

// AccessLogEntryMaker is a lazy constructor for access log entries.
type AccessLogEntryMaker func() (*auditv1.AccessLogEntry, error)

// DecisionLogEntryMaker is a lazy constructor for decision log entries.
type DecisionLogEntryMaker func() (*auditv1.DecisionLogEntry, error)

type AccessLogIterator interface {
	Next() (*auditv1.AccessLogEntry, error)
}

type DecisionLogIterator interface {
	Next() (*auditv1.DecisionLogEntry, error)
}

// Constructor for backends.
type Constructor func(context.Context) (Log, error)

// RegisterBackend registers an audit log backend.
func RegisterBackend(name string, cons Constructor) {
	backendsMu.Lock()
	backends[name] = cons
	backendsMu.Unlock()
}

// NewLog creates a new audit log.
func NewLog(ctx context.Context) (Log, error) {
	conf := &Conf{}

	if err := config.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to read audit configuration: %w", err)
	}

	if !conf.Enabled {
		return NewNopLog(), nil
	}

	backendsMu.RLock()
	cons, ok := backends[conf.Backend]
	backendsMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown backend [%s]", conf.Backend)
	}

	backend, err := cons(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend: %w", err)
	}

	return &logWrapper{conf: conf, backend: backend}, nil
}

// NewNopLog returns an audit log that does nothing.
func NewNopLog() Log {
	conf := &Conf{confHolder: confHolder{Enabled: false, AccessLogsEnabled: false, DecisionLogsEnabled: false}}
	return &logWrapper{conf: conf}
}

// logWrapper wraps the backends and enforces the config options.
type logWrapper struct {
	conf    *Conf
	backend Log
}

func (lw *logWrapper) WriteAccessLogEntry(ctx context.Context, entry AccessLogEntryMaker) error {
	if !lw.conf.AccessLogsEnabled {
		return nil
	}

	return lw.backend.WriteAccessLogEntry(ctx, entry)
}

func (lw *logWrapper) WriteDecisionLogEntry(ctx context.Context, entry DecisionLogEntryMaker) error {
	if !lw.conf.DecisionLogsEnabled {
		return nil
	}

	return lw.backend.WriteDecisionLogEntry(ctx, entry)
}

func (lw *logWrapper) LastNAccessLogEntries(ctx context.Context, n uint) AccessLogIterator {
	if !lw.conf.AccessLogsEnabled {
		return nopAccessLogIterator{}
	}

	return lw.backend.LastNAccessLogEntries(ctx, n)
}

func (lw *logWrapper) LastNDecisionLogEntries(ctx context.Context, n uint) DecisionLogIterator {
	if !lw.conf.DecisionLogsEnabled {
		return nopDecisionLogIterator{}
	}

	return lw.backend.LastNDecisionLogEntries(ctx, n)
}

func (lw *logWrapper) AccessLogEntriesBetween(ctx context.Context, from, to time.Time) AccessLogIterator {
	if !lw.conf.AccessLogsEnabled {
		return nopAccessLogIterator{}
	}

	return lw.backend.AccessLogEntriesBetween(ctx, from, to)
}

func (lw *logWrapper) DecisionLogEntriesBetween(ctx context.Context, from, to time.Time) DecisionLogIterator {
	if !lw.conf.DecisionLogsEnabled {
		return nopDecisionLogIterator{}
	}

	return lw.backend.DecisionLogEntriesBetween(ctx, from, to)
}

func (lw *logWrapper) AccessLogEntryByID(ctx context.Context, id ID) AccessLogIterator {
	if !lw.conf.AccessLogsEnabled {
		return nopAccessLogIterator{}
	}

	return lw.backend.AccessLogEntryByID(ctx, id)
}

func (lw *logWrapper) DecisionLogEntryByID(ctx context.Context, id ID) DecisionLogIterator {
	if !lw.conf.DecisionLogsEnabled {
		return nopDecisionLogIterator{}
	}

	return lw.backend.DecisionLogEntryByID(ctx, id)
}

func (lw *logWrapper) Close() {
	if lw.backend != nil {
		lw.backend.Close()
	}
}

// nopAccessLogIterator implements an AccessLogIterator that always returns nothing.
type nopAccessLogIterator struct{}

func (n nopAccessLogIterator) Next() (*auditv1.AccessLogEntry, error) {
	return nil, ErrIteratorClosed
}

// nopDecisionLogIterator implements a DecisionLogIterator that always returns nothing.
type nopDecisionLogIterator struct{}

func (n nopDecisionLogIterator) Next() (*auditv1.DecisionLogEntry, error) {
	return nil, ErrIteratorClosed
}
