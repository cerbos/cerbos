// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"strings"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"go.opentelemetry.io/contrib/propagators/autoprop"
	otelpropb3 "go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprop "go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
)

var noopCloseFn = func() error { return nil }

func InitTracing(ctx context.Context, conf *TracingConf, res *resource.Resource) (func() error, error) {
	if conf == nil {
		checkDeprecatedConf()
		return noopCloseFn, nil
	}

	if conf.SampleProbability == 0.0 {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return noopCloseFn, nil
	}

	var exporter *otlptrace.Exporter
	var err error

	switch conf.CollectorProtocol {
	case "grpc":
		var opts []otlptracegrpc.Option
		if conf.CollectorEndpoint != "" {
			opts = []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(conf.CollectorEndpoint)}
		}
		exporter, err = otlptracegrpc.New(ctx, opts...)
	case "http":
		var opts []otlptracehttp.Option
		if conf.CollectorEndpoint != "" {
			opts = []otlptracehttp.Option{otlptracehttp.WithEndpoint(conf.CollectorEndpoint)}
		}
		exporter, err = otlptracehttp.New(ctx, opts...)
	default:
		return noopCloseFn, fmt.Errorf("unknown collector protocol %q", conf.CollectorProtocol)
	}

	if err != nil {
		return noopCloseFn, fmt.Errorf("failed to initialize trace exporter: %w", err)
	}

	sampler := mkSampler(conf.SampleProbability)
	traceProvider := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exporter),
		tracesdk.WithSampler(sampler),
		tracesdk.WithResource(res),
	)

	otel.SetErrorHandler(otelErrHandler(func(err error) {
		zap.L().Named("otel").Warn("OpenTelemetry error", zap.Error(err))
	}))

	otel.SetTracerProvider(traceProvider)
	otel.SetTextMapPropagator(autoprop.NewTextMapPropagator(otelprop.TraceContext{}, otelprop.Baggage{}, otelpropb3.New()))

	return func() error {
		if err := traceProvider.Shutdown(context.TODO()); err != nil {
			zap.L().Warn("Failed to cleanly shutdown trace exporter", zap.Error(err))
			return err
		}

		return nil
	}, nil
}

func checkDeprecatedConf() {
	var deprecatedConf tracing.Conf
	if err := config.GetSection(&deprecatedConf); err != nil {
		zap.L().Warn("[OUTDATED CONFIG] Tracing is disabled. Failed to check for outdated tracing configuration", zap.Error(err))
		return
	}

	if deprecatedConf.Exporter != "" || deprecatedConf.Jaeger != nil || deprecatedConf.OTLP != nil {
		zap.L().Warn("[OUTDATED CONFIG] Tracing is disabled. Please migrate to the new OpenTelemetry configuration (see https://docs.cerbos.dev/cerbos/latest/configuration/otel)")
	}
}

func mkSampler(probability float64) tracesdk.Sampler {
	if probability == 0.0 {
		return tracesdk.NeverSample()
	}

	return sampler{s: tracesdk.ParentBased(tracesdk.TraceIDRatioBased(probability))}
}

type sampler struct {
	s tracesdk.Sampler
}

func (s sampler) ShouldSample(params tracesdk.SamplingParameters) tracesdk.SamplingResult {
	switch {
	case strings.HasPrefix(params.Name, "grpc."):
		return tracesdk.SamplingResult{Decision: tracesdk.Drop}
	case strings.HasPrefix(params.Name, "cerbos.svc.v1.CerbosPlaygroundService."):
		return tracesdk.SamplingResult{Decision: tracesdk.Drop}
	case strings.HasPrefix(params.Name, "/api/playground/"):
		return tracesdk.SamplingResult{Decision: tracesdk.Drop}
	default:
		return s.s.ShouldSample(params)
	}
}

func (s sampler) Description() string {
	return "CerbosCustomSampler"
}

type otelErrHandler func(err error)

func (o otelErrHandler) Handle(err error) {
	o(err)
}
