// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"sync"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/util"
)

type Sink interface {
	Enabled() bool
	AddTrace(trace *enginev1.Trace)
}

type Collector struct {
	traces []*enginev1.Trace
	mutex  sync.RWMutex
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Enabled() bool {
	return true
}

func (c *Collector) AddTrace(trace *enginev1.Trace) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.traces = append(c.traces, trace)
}

func (c *Collector) Traces() []*enginev1.Trace {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.traces
}

func TracesToBatch(traces []*enginev1.Trace) *enginev1.TraceBatch {
	if len(traces) == 0 {
		return nil
	}

	// Pre-size for typical unique component counts (usually small, ~100-500)
	defs := make([]*enginev1.Trace_Component, 0, 256)
	defIndex := make(map[uint64]uint32, 256)

	// First-tier cache: pointer -> hash (avoids recomputing hash for same pointer)
	ptrToHash := make(map[*enginev1.Trace_Component]uint64)

	intern := func(comp *enginev1.Trace_Component) uint32 {
		// Check pointer cache first
		key, ok := ptrToHash[comp]
		if !ok {
			key = util.HashPB(comp, nil)
			ptrToHash[comp] = key
		}

		// Check hash -> index cache
		if idx, ok := defIndex[key]; ok {
			return idx
		}
		idx := uint32(len(defs))
		defs = append(defs, comp)
		defIndex[key] = idx
		return idx
	}

	// Count total components for batch allocation
	totalComponents := 0
	for _, trace := range traces {
		totalComponents += len(trace.Components)
	}

	// Batch allocate all TraceEntry structs and indices to reduce allocations
	entryBuf := make([]enginev1.TraceEntry, len(traces))
	entries := make([]*enginev1.TraceEntry, len(traces))
	indicesBuf := make([]uint32, totalComponents)

	for i, trace := range traces {
		n := len(trace.Components)
		indices := indicesBuf[:n]
		indicesBuf = indicesBuf[n:]
		for j, comp := range trace.Components {
			indices[j] = intern(comp)
		}
		entryBuf[i].ComponentIndices = indices
		entryBuf[i].Event = trace.Event
		entries[i] = &entryBuf[i]
	}

	return &enginev1.TraceBatch{
		Definitions: defs,
		Entries:     entries,
	}
}
