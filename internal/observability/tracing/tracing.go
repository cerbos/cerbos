// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package tracing

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	otelsdk "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/semconv/v1.13.0/httpconv"
	"go.opentelemetry.io/otel/trace"

	"github.com/cerbos/cerbos/internal/engine/tracer"
)

func HTTPHandler(handler http.Handler, path string) http.Handler {
	return otelhttp.NewHandler(handler, path)
}

func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return otelsdk.Tracer("cerbos.dev/cerbos").Start(ctx, name)
}

func StartTracer(sink tracer.Sink) tracer.Context {
	return tracer.Start(sink)
}

func MarkFailed(span trace.Span, code int, err error) {
	if err != nil {
		span.RecordError(err)
	}

	c, desc := httpconv.ServerStatus(code)
	span.SetStatus(c, desc)
}

func RecordSpan(ctx context.Context, name string, fn func(context.Context, trace.Span)) {
	spanCtx, span := StartSpan(ctx, name)
	defer span.End()

	fn(spanCtx, span)
}

func RecordSpan1(ctx context.Context, name string, fn func(context.Context, trace.Span) error) error {
	spanCtx, span := StartSpan(ctx, name)
	defer span.End()

	err := fn(spanCtx, span)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	return err
}

func RecordSpan2[T any](ctx context.Context, name string, fn func(context.Context, trace.Span) (T, error)) (T, error) {
	spanCtx, span := StartSpan(ctx, name)
	defer span.End()

	result, err := fn(spanCtx, span)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	return result, err
}
