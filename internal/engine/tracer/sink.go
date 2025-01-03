// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"encoding/json"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

type ZapSink struct {
	log *zap.Logger
}

func NewZapSink(log *zap.Logger) *ZapSink {
	return &ZapSink{log: log}
}

func (zs *ZapSink) Enabled() bool {
	return zs.log.Core().Enabled(zapcore.DebugLevel)
}

func (zs *ZapSink) AddTrace(trace *enginev1.Trace) {
	if ce := zs.log.Check(zapcore.DebugLevel, "Trace event"); ce != nil {
		ce.Write(zapTrace(trace))
	}
}

func zapTrace(trace *enginev1.Trace) zap.Field {
	data, err := protojson.Marshal(trace)
	if err != nil {
		return zap.Error(fmt.Errorf("failed to marshal trace to JSON: %w", err))
	}

	return zap.Any("trace", json.RawMessage(data))
}
