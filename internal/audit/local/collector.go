// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"sync"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
)

type collector interface {
	add([]byte) error
	done(error)
}

type accessLogEntryCollector struct {
	buffer   chan *auditv1.AccessLogEntry
	doneOnce sync.Once
	mu       sync.RWMutex
	err      error
}

func newAccessLogEntryCollector() *accessLogEntryCollector {
	return &accessLogEntryCollector{
		buffer: make(chan *auditv1.AccessLogEntry, 1),
	}
}

func (a *accessLogEntryCollector) add(v []byte) error {
	entry := &auditv1.AccessLogEntry{}
	if err := entry.UnmarshalVT(v); err != nil {
		return err
	}

	a.buffer <- entry
	return nil
}

func (a *accessLogEntryCollector) done(err error) {
	a.doneOnce.Do(func() {
		close(a.buffer)
		a.mu.Lock()
		if err != nil {
			a.err = err
		} else {
			a.err = audit.ErrIteratorClosed
		}
		a.mu.Unlock()
	})
}

func (a *accessLogEntryCollector) Next() (*auditv1.AccessLogEntry, error) {
	entry, ok := <-a.buffer
	if ok {
		return entry, nil
	}

	a.mu.RLock()
	err := a.err
	a.mu.RUnlock()

	return nil, err
}

type decisionLogEntryCollector struct {
	buffer   chan *auditv1.DecisionLogEntry
	doneOnce sync.Once
	mu       sync.RWMutex
	err      error
}

func newDecisionLogEntryCollector() *decisionLogEntryCollector {
	return &decisionLogEntryCollector{
		buffer: make(chan *auditv1.DecisionLogEntry, 1),
	}
}

func (d *decisionLogEntryCollector) add(v []byte) error {
	entry := &auditv1.DecisionLogEntry{}
	if err := entry.UnmarshalVT(v); err != nil {
		return err
	}

	d.buffer <- entry
	return nil
}

func (d *decisionLogEntryCollector) done(err error) {
	d.doneOnce.Do(func() {
		close(d.buffer)
		d.mu.Lock()
		if err != nil {
			d.err = err
		} else {
			d.err = audit.ErrIteratorClosed
		}
		d.mu.Unlock()
	})
}

func (d *decisionLogEntryCollector) Next() (*auditv1.DecisionLogEntry, error) {
	entry, ok := <-d.buffer
	if ok {
		return entry, nil
	}

	d.mu.RLock()
	err := d.err
	d.mu.RUnlock()

	return nil, err
}
