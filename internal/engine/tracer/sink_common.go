// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"sync"

	"github.com/cespare/xxhash/v2"

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
	defIndexPool       = sync.Pool{New: func() any { return make(map[uint64]uint32, defaultCapacity) }}
	compHashToHashPool = sync.Pool{New: func() any { return make(map[uint64]uint64, defaultCapacity) }}
	serBufPool         = sync.Pool{New: func() any { b := make([]byte, 0, defaultCapacity); return &b }}
	hasherPool         = sync.Pool{New: func() any { return xxhash.New() }}
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

func hashPB(comp *enginev1.Trace_Component) uint64 {
	hasher := hasherPool.Get().(*xxhash.Digest) //nolint:forcetypeassert
	comp.HashPB(hasher, nil)
	return hasher.Sum64()
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

	defIndex := defIndexPool.Get().(map[uint64]uint32)             //nolint:forcetypeassert
	compHashToHash := compHashToHashPool.Get().(map[uint64]uint64) //nolint:forcetypeassert
	serBufPtr := serBufPool.Get().(*[]byte)                        //nolint:forcetypeassert
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
			compHashToHashKey := hashPB(comp)
			key, ok := compHashToHash[compHashToHashKey]
			if !ok {
				key, serBuf = hashComponentVT(comp, hasher, serBuf)
				compHashToHash[compHashToHashKey] = key
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
	clear(compHashToHash)
	defIndexPool.Put(defIndex)
	compHashToHashPool.Put(compHashToHash)
	*serBufPtr = serBuf[:0]
	serBufPool.Put(serBufPtr)
	hasherPool.Put(hasher)

	return &enginev1.TraceBatch{
		Definitions: defs,
		Entries:     entries,
	}
}

func TraceComponentDefinitionsToMap(definitions []*enginev1.Trace_Component) map[uint32]*enginev1.Trace_Component {
	if len(definitions) == 0 {
		return nil
	}

	definitionsMap := make(map[uint32]*enginev1.Trace_Component)
	var idx uint32 = 0
	for _, definition := range definitions {
		definitionsMap[idx] = definition
		idx++
	}

	return definitionsMap
}
