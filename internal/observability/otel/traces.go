// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.opentelemetry.io/contrib/propagators/autoprop"
	otelpropb3 "go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprop "go.opentelemetry.io/otel/propagation"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/util"
)

var noopCloseFn = func() error { return nil }

func InitTraces(ctx context.Context, env Env) (func() error, error) {
	if isDisabled(env) {
		otel.SetTracerProvider(noop.NewTracerProvider())
		zap.L().Named("otel").Info("Traces disabled because OpenTelemetry SDK is disabled by environment variable")
		return noopCloseFn, nil
	}

	var exporter *otlptrace.Exporter
	var err error
	protocol := env.GetOrDefault(TracesProtocolEV, GRPCProtocol)
	switch protocol {
	case GRPCProtocol:
		exporter, err = otlptracegrpc.New(ctx)
	case HTTPProtobufProtocol:
		exporter, err = otlptracehttp.New(ctx)
	default:
		err = fmt.Errorf("otlp exporter protocol %q is not supported", protocol)
	}
	if err != nil {
		return noopCloseFn, fmt.Errorf("failed to initialize trace exporter: %w", err)
	}

	return InitTracesWithExporter(ctx, env, exporter)
}

func InitTracesWithExporter(ctx context.Context, env Env, exporter tracesdk.SpanExporter) (func() error, error) {
	sampler, err := createSampler(env)
	if err != nil {
		return noopCloseFn, fmt.Errorf("failed to initialize trace sampler: %w", err)
	}

	res, err := NewResource(ctx, env.GetOrDefault(ServiceNameEV, util.AppName))
	if err != nil {
		return noopCloseFn, fmt.Errorf("failed to create Otel resource: %w", err)
	}

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

func createSampler(env Env) (sampler tracesdk.Sampler, err error) {
	samplerImpl := env.GetOrDefault(TracesSamplerEV, ParentBasedTraceIDRatioSampler)
	switch samplerImpl {
	case AlwaysOffSampler:
		return decorateSampler(tracesdk.NeverSample()), nil
	case AlwaysOnSampler:
		return decorateSampler(tracesdk.AlwaysSample()), nil
	case ParentBasedAlwaysOffSampler:
		return decorateSampler(tracesdk.ParentBased(tracesdk.NeverSample())), nil
	case ParentBasedAlwaysOnSampler:
		return decorateSampler(tracesdk.ParentBased(tracesdk.AlwaysSample())), nil
	case ParentBasedTraceIDRatioSampler:
		f := env.GetOrDefault(TracesSamplerArgEV, "1.0")
		sampleFraction, err := strconv.ParseFloat(f, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trace ID ratio value %q: %w", f, err)
		}
		return decorateSampler(tracesdk.ParentBased(tracesdk.TraceIDRatioBased(sampleFraction))), nil
	case TraceIDRatioSampler:
		f := env.GetOrDefault(TracesSamplerArgEV, "1.0")
		sampleFraction, err := strconv.ParseFloat(f, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trace ID ratio value %q: %w", f, err)
		}
		return decorateSampler(tracesdk.TraceIDRatioBased(sampleFraction)), nil
	default:
		return nil, fmt.Errorf("trace sampler %q is not supported", samplerImpl)
	}
}

func decorateSampler(s tracesdk.Sampler) tracesdk.Sampler {
	return sampler{s: s}
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
