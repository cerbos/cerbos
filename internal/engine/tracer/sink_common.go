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

	var defs []*enginev1.Trace_Component
	defIndex := make(map[uint64]uint32)

	intern := func(comp *enginev1.Trace_Component) uint32 {
		key := util.HashPB(comp, nil)
		if idx, ok := defIndex[key]; ok {
			return idx
		}
		idx := uint32(len(defs))
		defs = append(defs, comp)
		defIndex[key] = idx
		return idx
	}

	entries := make([]*enginev1.TraceEntry, 0, len(traces))
	for _, trace := range traces {
		indices := make([]uint32, len(trace.Components))
		for i, comp := range trace.Components {
			indices[i] = intern(comp)
		}
		entries = append(entries, &enginev1.TraceEntry{
			ComponentIndices: indices,
			Event:            trace.Event,
		})
	}

	return &enginev1.TraceBatch{
		Definitions: defs,
		Entries:     entries,
	}
}
