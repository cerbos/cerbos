// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
)

type Tracer interface {
	Trace(componentName) TraceContext
	LogOutput(context.Context)
}

func NewTracer(enabled bool) Tracer {
	if enabled {
		return &tracer{trace: &runtimev1.ExecutionTrace{}}
	}
	return noopTracer{}
}

type noopTracer struct{}

func (noopTracer) Trace(_ componentName) TraceContext {
	return noopTraceCtx{}
}

func (noopTracer) LogOutput(_ context.Context) {}

type tracer struct {
	trace *runtimev1.ExecutionTrace
}

func (t *tracer) Trace(name componentName) TraceContext {
	return &traceCtx{parent: t, component: name()}
}

func (t *tracer) addLogEntry(entry *runtimev1.ExecutionTrace_LogEntry) {
	t.trace.LogEntries = append(t.trace.LogEntries, entry)
}

func (t *tracer) LogOutput(ctx context.Context) {
	buf := new(bytes.Buffer)
	for _, entry := range t.trace.LogEntries {
		level := "I"
		switch entry.Level {
		case runtimev1.ExecutionTrace_LOG_LEVEL_DEBUG:
			level = "D"
		case runtimev1.ExecutionTrace_LOG_LEVEL_INFO:
			level = "I"
		case runtimev1.ExecutionTrace_LOG_LEVEL_WARN:
			level = "W"
		case runtimev1.ExecutionTrace_LOG_LEVEL_ERROR:
			level = "E"
		}

		if entry.Error != "" {
			fmt.Fprintf(buf, "%s [%s] => %s (%s)\n", level, entry.Component, entry.Msg, entry.Error)
		} else {
			fmt.Fprintf(buf, "%s [%s] => %s\n", level, entry.Component, entry.Msg)
		}
	}

	logging.FromContext(ctx).Info(buf.String())
}

type TraceContext interface {
	Trace(name componentName) TraceContext
	Activate(cause string)
	Skip(cause string)
	SkipErr(err error)
	Debug(msg string, param ...interface{})
	Info(msg string, param ...interface{})
	Warn(msg string, param ...interface{})
	Error(err error, msg string, param ...interface{})
}

type noopTraceCtx struct{}

func (noopTraceCtx) Trace(name componentName) TraceContext {
	return noopTraceCtx{}
}

func (noopTraceCtx) Activate(_ string) {}

func (noopTraceCtx) Skip(_ string) {}

func (noopTraceCtx) SkipErr(_ error) {}

func (noopTraceCtx) Debug(_ string, _ ...interface{}) {}

func (noopTraceCtx) Info(_ string, _ ...interface{}) {}

func (noopTraceCtx) Warn(_ string, _ ...interface{}) {}

func (noopTraceCtx) Error(_ error, _ string, _ ...interface{}) {}

type traceCtx struct {
	parent    *tracer
	component string
}

func (tc *traceCtx) Trace(name componentName) TraceContext {
	return &traceCtx{parent: tc.parent, component: fmt.Sprintf("%s>%s", tc.component, name())}
}

func (tc *traceCtx) Activate(cause string) {
	tc.Info("[ACTIVATED] %s", cause)
}

func (tc *traceCtx) Skip(cause string) {
	tc.Info("[SKIP] %s", cause)
}

func (tc *traceCtx) SkipErr(err error) {
	tc.Info("[SKIP] ERROR: %v", err)
}

func (tc *traceCtx) Debug(msg string, param ...interface{}) {
	tc.parent.addLogEntry(&runtimev1.ExecutionTrace_LogEntry{
		Component: tc.component,
		Level:     runtimev1.ExecutionTrace_LOG_LEVEL_DEBUG,
		Msg:       fmt.Sprintf(msg, param...),
	})
}

func (tc *traceCtx) Info(msg string, param ...interface{}) {
	tc.parent.addLogEntry(&runtimev1.ExecutionTrace_LogEntry{
		Component: tc.component,
		Level:     runtimev1.ExecutionTrace_LOG_LEVEL_INFO,
		Msg:       fmt.Sprintf(msg, param...),
	})
}

func (tc *traceCtx) Warn(msg string, param ...interface{}) {
	tc.parent.addLogEntry(&runtimev1.ExecutionTrace_LogEntry{
		Component: tc.component,
		Level:     runtimev1.ExecutionTrace_LOG_LEVEL_WARN,
		Msg:       fmt.Sprintf(msg, param...),
	})
}

func (tc *traceCtx) Error(err error, msg string, param ...interface{}) {
	tc.parent.addLogEntry(&runtimev1.ExecutionTrace_LogEntry{
		Component: tc.component,
		Level:     runtimev1.ExecutionTrace_LOG_LEVEL_ERROR,
		Msg:       fmt.Sprintf(msg, param...),
		Error:     err.Error(),
	})
}

type componentName func() string

var (
	cnVariables componentName = func() string { return "variables" }
	cnCondition componentName = func() string { return "condition" }
	cnCondAll   componentName = func() string { return "condition_all" }
	cnCondAny   componentName = func() string { return "condition_any" }
	cnCondNone  componentName = func() string { return "condition_none" }
)

func cnPolicy(fqn string, scope []string) componentName {
	return func() string {
		if len(scope) > 0 {
			return fmt.Sprintf("policy=%s scope=%s", fqn, strings.Join(scope, "."))
		}
		return fmt.Sprintf("policy=%s", fqn)
	}
}

func cnDerivedRole(dr string) componentName { return kvStr("derived_role", dr) }

func cnRule(name string) componentName { return kvStr("rule", name) }

func cnAction(name string) componentName { return kvStr("action", name) }

func cnResource(name string) componentName { return kvStr("resource", name) }

func cnVariableExpr(name, expr string) componentName {
	return func() string { return fmt.Sprintf("var=%s expr=`%s`", name, expr) }
}

func cnCondExpr(expr string) componentName { return kvStr("expr", expr) }

func cnCondN(i int) componentName { return func() string { return fmt.Sprintf("expr#%02d", i+1) } }

func kvStr(key, value string) componentName {
	return func() string { return fmt.Sprintf("%s=%s", key, value) }
}
