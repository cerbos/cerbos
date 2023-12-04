// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	otelsdk "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/semconv/v1.13.0/httpconv"
	"go.opentelemetry.io/otel/trace"
)

func HTTPHandler(handler http.Handler, path string) http.Handler {
	return otelhttp.NewHandler(handler, path)
}

func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return otelsdk.Tracer("cerbos.dev/cerbos").Start(ctx, name)
}

func MarkFailed(span trace.Span, code int, err error) {
	if err != nil {
		span.RecordError(err)
	}

	c, desc := httpconv.ServerStatus(code)
	span.SetStatus(c, desc)
}
