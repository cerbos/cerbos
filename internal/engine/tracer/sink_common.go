// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"slices"
	"sync"

	"github.com/cespare/xxhash/v2"
	"google.golang.org/protobuf/encoding/protojson"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
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

const defaultCapacity = 256

var (
	defIndexPool = sync.Pool{New: func() any { return make(map[uint64]uint32, defaultCapacity) }}
	ptrHashPool  = sync.Pool{New: func() any { return make(map[*enginev1.Trace_Component]uint64, defaultCapacity) }}
	serBufPool   = sync.Pool{New: func() any { b := make([]byte, 0, defaultCapacity); return &b }}
	hasherPool   = sync.Pool{New: func() any { return xxhash.New() }}
)

func hashComponentVT(comp *enginev1.Trace_Component, hasher *xxhash.Digest, buf []byte) (uint64, []byte) {
	size := comp.SizeVT()
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}

	_, _ = comp.MarshalToSizedBufferVT(buf)
	hasher.Reset()
	_, _ = hasher.Write(buf)

	return hasher.Sum64(), buf
}

func TracesToBatch(traces []*enginev1.Trace) *enginev1.TraceBatch {
	if len(traces) == 0 {
		return nil
	}

	totalComponents := 0
	for _, trace := range traces {
		totalComponents += len(trace.Components)
	}

	defs := make([]*enginev1.Trace_Component, 0, defaultCapacity)

	defIndex := defIndexPool.Get().(map[uint64]uint32)                    //nolint:forcetypeassert
	ptrToHash := ptrHashPool.Get().(map[*enginev1.Trace_Component]uint64) //nolint:forcetypeassert
	serBufPtr := serBufPool.Get().(*[]byte)                               //nolint:forcetypeassert
	serBuf := *serBufPtr
	hasher := hasherPool.Get().(*xxhash.Digest) //nolint:forcetypeassert

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
				key, serBuf = hashComponentVT(comp, hasher, serBuf)
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
	*serBufPtr = serBuf[:0]
	serBufPool.Put(serBufPtr)
	hasherPool.Put(hasher)

	return &enginev1.TraceBatch{
		Definitions: defs,
		Entries:     entries,
	}
}

func BatchToTraces(batch *enginev1.TraceBatch) []*enginev1.Trace {
	if batch == nil || len(batch.Entries) == 0 {
		return nil
	}

	traces := make([]*enginev1.Trace, len(batch.Entries))
	for i, entry := range batch.Entries {
		components := make([]*enginev1.Trace_Component, len(entry.ComponentIndices))
		for j, idx := range entry.ComponentIndices {
			components[j] = batch.Definitions[idx]
		}
		traces[i] = &enginev1.Trace{
			Components: components,
			Event:      entry.Event,
		}
	}

	return traces
}
