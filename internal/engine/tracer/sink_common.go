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

var (
	defIndexPool = sync.Pool{New: func() any { return make(map[uint64]uint32, 256) }}
	ptrHashPool  = sync.Pool{New: func() any { return make(map[*enginev1.Trace_Component]uint64, 256) }}
)

func TracesToBatch(traces []*enginev1.Trace) *enginev1.TraceBatch {
	if len(traces) == 0 {
		return nil
	}

	totalComponents := 0
	for _, trace := range traces {
		totalComponents += len(trace.Components)
	}

	defs := make([]*enginev1.Trace_Component, 0, 256)

	defIndex := defIndexPool.Get().(map[uint64]uint32)
	ptrToHash := ptrHashPool.Get().(map[*enginev1.Trace_Component]uint64)

	entryBuf := make([]enginev1.TraceEntry, len(traces))
	entries := make([]*enginev1.TraceEntry, len(traces))
	indicesBuf := make([]uint32, totalComponents)

	for i, trace := range traces {
		n := len(trace.Components)
		indices := indicesBuf[:n]
		indicesBuf = indicesBuf[n:]
		for j, comp := range trace.Components {
			key, ok := ptrToHash[comp]
			if !ok {
				key = util.HashPB(comp, nil)
				ptrToHash[comp] = key
			}
			if idx, ok := defIndex[key]; ok {
				indices[j] = idx
			} else {
				idx := uint32(len(defs))
				defs = append(defs, comp)
				defIndex[key] = idx
				indices[j] = idx
			}
		}
		entryBuf[i].ComponentIndices = indices
		entryBuf[i].Event = trace.Event
		entries[i] = &entryBuf[i]
	}

	clear(defIndex)
	clear(ptrToHash)
	defIndexPool.Put(defIndex)
	ptrHashPool.Put(ptrToHash)

	return &enginev1.TraceBatch{
		Definitions: defs,
		Entries:     entries,
	}
}
