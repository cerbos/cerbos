// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
)

const (
	actionComponent      = "action=%s"
	condAllComponent     = "conditionAll"
	condAnyComponent     = "conditionAny"
	condNoneComponent    = "conditionNone"
	conditionComponent   = "condition"
	derivedRoleComponent = "derivedRole=%s"
	exprComponent        = "expr=`%s`"
	nthCondComponent     = "cond-%02d"
	policyComponent      = "policy=%s"
	resourceComponent    = "resource=%s"
	ruleComponent        = "rule=%s"
	varComponent         = "%s:=%s"
	variablesComponent   = "variables"

	ActivatedKey = "activated"
	EffectKey    = "effect"
	ErrorKey     = "error"
	MessageKey   = "message"
	ResultKey    = "result"
)

// KV is a function that returns a key-value pair.
type KV func() (string, string)

// KVError produces a KV for an error.
func KVError(err error) KV {
	return func() (string, string) { return ErrorKey, err.Error() }
}

// KVMsg produces a KV for a free-form message.
func KVMsg(msg string, params ...interface{}) KV {
	return func() (string, string) { return MessageKey, fmt.Sprintf(msg, params...) }
}

// KVSkip produces a KV for skipping evaluation.
func KVSkip() KV {
	return func() (string, string) { return ActivatedKey, "false" }
}

// KVActivated produces a KV for component activation.
func KVActivated() KV {
	return func() (string, string) { return ActivatedKey, "true" }
}

// KVEffect produces a KV for setting default effect.
func KVEffect(effect effectv1.Effect) KV {
	return func() (string, string) { return EffectKey, effect.String() }
}

// KVResult produces a KV for a condition result.
func KVResult(result bool) KV {
	return func() (string, string) { return ResultKey, strconv.FormatBool(result) }
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

// WriterTraceSink implements TraceSink using an io.Writer.
type WriterTraceSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriterTraceSink(w io.Writer) *WriterTraceSink {
	return &WriterTraceSink{w: w}
}

func (wts *WriterTraceSink) Enabled() bool {
	return true
}

func (wts *WriterTraceSink) WriteEvent(component []string, data ...KV) {
	buf := new(bytes.Buffer)
	fmt.Fprintln(buf, strings.Join(component, " > "))
	for _, kv := range data {
		k, v := kv()
		fmt.Fprintf(buf, "\t%s -> %s\n", k, v)
	}
	fmt.Fprintln(buf)

	wts.mu.Lock()
	_, _ = io.Copy(wts.w, buf)
	wts.mu.Unlock()
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
