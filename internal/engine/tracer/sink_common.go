// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"sync"

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

type componentKey struct {
	detail1 string
	detail2 string
	kind    enginev1.Trace_Component_Kind
	index   uint32
}

func TracesToBatch(traces []*enginev1.Trace) *enginev1.TraceBatch {
	if len(traces) == 0 {
		return nil
	}

	var defs []*enginev1.Trace_Component
	defIndex := make(map[componentKey]uint32)

	intern := func(comp *enginev1.Trace_Component) uint32 {
		key := makeComponentKey(comp)
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

func makeComponentKey(c *enginev1.Trace_Component) componentKey {
	key := componentKey{kind: c.Kind}
	switch d := c.Details.(type) {
	case *enginev1.Trace_Component_Action:
		key.detail1 = d.Action
	case *enginev1.Trace_Component_DerivedRole:
		key.detail1 = d.DerivedRole
	case *enginev1.Trace_Component_Expr:
		key.detail1 = d.Expr
	case *enginev1.Trace_Component_Index:
		key.index = d.Index
	case *enginev1.Trace_Component_Policy:
		key.detail1 = d.Policy
	case *enginev1.Trace_Component_Resource:
		key.detail1 = d.Resource
	case *enginev1.Trace_Component_Rule:
		key.detail1 = d.Rule
	case *enginev1.Trace_Component_Scope:
		key.detail1 = d.Scope
	case *enginev1.Trace_Component_Variable_:
		key.detail1 = d.Variable.Name
		key.detail2 = d.Variable.Expr
	case *enginev1.Trace_Component_Output:
		key.detail1 = d.Output
	case *enginev1.Trace_Component_RolePolicyScope:
		key.detail1 = d.RolePolicyScope
	case *enginev1.Trace_Component_Role:
		key.detail1 = d.Role
	}
	return key
}
