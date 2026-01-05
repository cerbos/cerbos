// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/sourcegraph/conc/pool"
	"go.uber.org/zap"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/metrics"
)

const (
	KindAccess   = "access"
	KindDecision = "decision"
)

var (
	ErrIteratorClosed = errors.New("iterator closed")

	backendsMu sync.RWMutex
	backends   = map[string]Constructor{}
)

type Info interface {
	Backend() string
	Enabled() bool
}

type Log interface {
	Info
	io.Closer
	WriteAccessLogEntry(context.Context, AccessLogEntryMaker) error
	WriteDecisionLogEntry(context.Context, DecisionLogEntryMaker) error
}

type QueryableLog interface {
	Log
	LastNAccessLogEntries(context.Context, uint) AccessLogIterator
	LastNDecisionLogEntries(context.Context, uint) DecisionLogIterator
	AccessLogEntriesBetween(context.Context, time.Time, time.Time) AccessLogIterator
	DecisionLogEntriesBetween(context.Context, time.Time, time.Time) DecisionLogIterator
	AccessLogEntryByID(context.Context, ID) AccessLogIterator
	DecisionLogEntryByID(context.Context, ID) DecisionLogIterator
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
type Constructor func(context.Context, *config.Wrapper, DecisionLogEntryFilter) (Log, error)

// RegisterBackend registers an audit log backend.
func RegisterBackend(name string, cons Constructor) {
	backendsMu.Lock()
	backends[name] = cons
	backendsMu.Unlock()
}

// GetBackend returns the constructor for the given driver.
func GetBackend(name string) (Constructor, error) {
	backendsMu.RLock()
	defer backendsMu.RUnlock()

	cons, exists := backends[name]
	if exists {
		return cons, nil
	}

	return nil, fmt.Errorf("no such audit backend: %s", name)
}

// NewLog creates a new audit log.
func NewLog(ctx context.Context) (Log, error) {
	return NewLogFromConf(ctx, config.Global())
}

func NewLogFromConf(ctx context.Context, confW *config.Wrapper) (Log, error) {
	conf := new(Conf)
	if err := confW.GetSection(conf); err != nil {
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

	decisionFilter := NewDecisionLogEntryFilterFromConf(conf)
	backend, err := cons(ctx, confW, decisionFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend: %w", err)
	}

	lw := newLogWrapper(conf, backend)
	if q, ok := backend.(QueryableLog); ok {
		return &queryableLogWrapper{logWrapper: lw, queryable: q}, nil
	}

	return lw, nil
}

// NewNopLog returns an audit log that does nothing.
func NewNopLog() Log {
	conf := &Conf{confHolder: confHolder{Enabled: false, AccessLogsEnabled: false, DecisionLogsEnabled: false}}
	return newLogWrapper(conf, nil)
}

func newLogWrapper(conf *Conf, backend Log) *logWrapper {
	lw := &logWrapper{conf: conf}
	if backend != nil {
		lw.backend = backend
		lw.pool = pool.New().WithMaxGoroutines(runtime.NumCPU())
	}

	return lw
}

// logWrapper wraps the backends and enforces the config options.
type logWrapper struct {
	conf    *Conf
	backend Log
	pool    *pool.Pool
}

func (lw *logWrapper) Backend() string {
	return lw.conf.Backend
}

func (lw *logWrapper) Enabled() bool {
	return lw.conf.Enabled
}

func (lw *logWrapper) WriteAccessLogEntry(ctx context.Context, entry AccessLogEntryMaker) error {
	if !lw.conf.AccessLogsEnabled {
		return nil
	}

	ctx = context.WithoutCancel(ctx)

	lw.pool.Go(func() {
		if err := lw.backend.WriteAccessLogEntry(ctx, entry); err != nil {
			metrics.Inc(ctx, metrics.AuditErrorCount(), metrics.KindKey(KindAccess))
			logging.FromContext(ctx).Warn("Failed to write access log entry", zap.Error(err))
		}
	})

	return nil
}

func (lw *logWrapper) WriteDecisionLogEntry(ctx context.Context, entry DecisionLogEntryMaker) error {
	if !lw.conf.DecisionLogsEnabled {
		return nil
	}

	ctx = context.WithoutCancel(ctx)

	lw.pool.Go(func() {
		if err := lw.backend.WriteDecisionLogEntry(ctx, entry); err != nil {
			metrics.Inc(ctx, metrics.AuditErrorCount(), metrics.KindKey(KindDecision))
			logging.FromContext(ctx).Warn("Failed to write decision log entry", zap.Error(err))
		}
	})

	return nil
}

func (lw *logWrapper) Close() error {
	if lw.backend != nil {
		lw.pool.Wait()
		return lw.backend.Close()
	}
	return nil
}

type queryableLogWrapper struct {
	*logWrapper
	queryable QueryableLog
}

func (qlw *queryableLogWrapper) LastNAccessLogEntries(ctx context.Context, n uint) AccessLogIterator {
	if !qlw.conf.AccessLogsEnabled {
		return nopAccessLogIterator{}
	}

	return qlw.queryable.LastNAccessLogEntries(ctx, n)
}

func (qlw *queryableLogWrapper) LastNDecisionLogEntries(ctx context.Context, n uint) DecisionLogIterator {
	if !qlw.conf.DecisionLogsEnabled {
		return nopDecisionLogIterator{}
	}

	return qlw.queryable.LastNDecisionLogEntries(ctx, n)
}

func (qlw *queryableLogWrapper) AccessLogEntriesBetween(ctx context.Context, from, to time.Time) AccessLogIterator {
	if !qlw.conf.AccessLogsEnabled {
		return nopAccessLogIterator{}
	}

	return qlw.queryable.AccessLogEntriesBetween(ctx, from, to)
}

func (qlw *queryableLogWrapper) DecisionLogEntriesBetween(ctx context.Context, from, to time.Time) DecisionLogIterator {
	if !qlw.conf.DecisionLogsEnabled {
		return nopDecisionLogIterator{}
	}

	return qlw.queryable.DecisionLogEntriesBetween(ctx, from, to)
}

func (qlw *queryableLogWrapper) AccessLogEntryByID(ctx context.Context, id ID) AccessLogIterator {
	if !qlw.conf.AccessLogsEnabled {
		return nopAccessLogIterator{}
	}

	return qlw.queryable.AccessLogEntryByID(ctx, id)
}

func (qlw *queryableLogWrapper) DecisionLogEntryByID(ctx context.Context, id ID) DecisionLogIterator {
	if !qlw.conf.DecisionLogsEnabled {
		return nopDecisionLogIterator{}
	}

	return qlw.queryable.DecisionLogEntryByID(ctx, id)
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
