// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
)

const (
	traceCondition = "condition"
	traceCondAll   = "conditionAll"
	traceCondAny   = "conditionAny"
	traceCondNone  = "conditionNone"
	traceVariables = "variables"
)

// KV is a function that returns a key-value pair.
type KV func() (string, string)

// KVError produces a KV for an error.
func KVError(err error) KV {
	return func() (string, string) { return "error", err.Error() }
}

// KVMsg produces a KV for a free-form message.
func KVMsg(msg string, params ...interface{}) KV {
	return func() (string, string) { return "message", fmt.Sprintf(msg, params...) }
}

// KVSkip produces a KV for skipping evaluation.
func KVSkip() KV {
	return func() (string, string) { return "activated", "false" }
}

// KVActivated produces a KV for component activation.
func KVActivated() KV {
	return func() (string, string) { return "activated", "true" }
}

// KVEffect produces a KV for setting default effect.
func KVEffect(effect effectv1.Effect) KV {
	return func() (string, string) { return "effect", effect.String() }
}

// TraceSink is the interface for sinks that receive trace events from the engine.
type TraceSink interface {
	Enabled() bool
	WriteEvent(component []string, data ...KV)
}

// NoopTraceSink implements a sink that does nothing.
type NoopTraceSink struct{}

func (NoopTraceSink) Enabled() bool { return false }

func (NoopTraceSink) WriteEvent(component []string, data ...KV) {}

// ZapTraceSink implements TraceSink using a Zap logger.
type ZapTraceSink struct {
	log *zap.Logger
}

func NewZapTraceSink(log *zap.Logger) *ZapTraceSink {
	return &ZapTraceSink{log: log}
}

func (zts *ZapTraceSink) Enabled() bool {
	return zts.log.Core().Enabled(zapcore.DebugLevel)
}

func (zts *ZapTraceSink) WriteEvent(component []string, data ...KV) {
	if ce := zts.log.With(zap.Strings("component", component)).Check(zapcore.DebugLevel, "Trace event"); ce != nil {
		f := make([]zapcore.Field, len(data))
		for i, kv := range data {
			k, v := kv()
			f[i] = zap.String(k, v)
		}
		ce.Write(f...)
	}
}

type tracer struct {
	enabled bool
	sink    TraceSink
}

func newTracer(sink TraceSink) *tracer {
	return &tracer{enabled: sink.Enabled(), sink: sink}
}

func (t *tracer) beginTrace(nameFormat string, params ...interface{}) *traceContext {
	if !t.enabled {
		return noopTraceCtx
	}

	return &traceContext{enabled: true, component: []string{fmt.Sprintf(nameFormat, params...)}, sink: t.sink}
}

type traceContext struct {
	enabled   bool
	component []string
	sink      TraceSink
}

var noopTraceCtx = &traceContext{enabled: false}

func (tc *traceContext) beginTrace(nameFormat string, params ...interface{}) *traceContext {
	if !tc.enabled {
		return noopTraceCtx
	}

	return &traceContext{enabled: true, component: join(tc.component, fmt.Sprintf(nameFormat, params...)), sink: tc.sink}
}

func (tc *traceContext) writeEvent(data ...KV) {
	if !tc.enabled {
		return
	}

	tc.sink.WriteEvent(tc.component, data...)
}

func join(a []string, b string) []string {
	c := make([]string, len(a)+1)
	copy(c, a)
	c[len(a)] = b

	return c
}
