// Copyright 2021-2026 Zenauth Ltd.
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

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/util"
)

func InitTracesWithExporter(ctx context.Context, env Env, exporter tracesdk.SpanExporter) (func() error, error) {
	return doInitTraces(ctx, env, exporter)
}

func InitTraces(ctx context.Context, env Env) (func() error, error) {
	checkOutdatedConfig()

	if _, endpointDefined := env.Get(TracesEndpointEV); !endpointDefined {
		zap.L().Named("otel").Warn("Disabling OTLP traces because neither OTEL_EXPORTER_OTLP_ENDPOINT nor OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is defined")
		otel.SetTracerProvider(noop.NewTracerProvider())
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
		return nil, fmt.Errorf("failed to initialize trace exporter: %w", err)
	}

	zap.S().Named("otel").Infof("Initialized OTLP trace exporter with protocol=%s", protocol)
	return doInitTraces(ctx, env, exporter)
}

func checkOutdatedConfig() {
	var oldConf struct{}
	// if the tracing block exists, this would result in an error because it cannot be unmarshaled into a struct{}
	if err := config.Get("tracing", &oldConf); err != nil {
		zap.L().Named("otel").Warn("[UNSUPPORTED CONFIG] Traces must be configured using OpenTelemetry environment variables. The `tracing` configuration block is no longer supported. See https://docs.cerbos.dev/cerbos/latest/configuration/observability#traces")
	}
}

func doInitTraces(ctx context.Context, env Env, exporter tracesdk.SpanExporter) (func() error, error) {
	res, err := newResource(ctx, env.GetOrDefault(ServiceNameEV, util.AppName))
	if err != nil {
		return nil, fmt.Errorf("failed to create Otel resource: %w", err)
	}

	sampler, err := createSampler(env)
	if err != nil {
		return noopCloseFn, fmt.Errorf("failed to initialize trace sampler: %w", err)
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
		if err := traceProvider.Shutdown(context.Background()); err != nil {
			zap.L().Warn("Failed to cleanly shutdown trace exporter", zap.Error(err))
			return err
		}

		return nil
	}, nil
}

func createSampler(env Env) (sampler tracesdk.Sampler, err error) {
	log := zap.L().Named("otel")
	samplerImpl := env.GetOrDefault(TracesSamplerEV, ParentBasedAlwaysOffSampler)
	switch samplerImpl {
	case AlwaysOffSampler:
		log.Debug("Using always off sampler")
		return decorateSampler(tracesdk.NeverSample()), nil
	case AlwaysOnSampler:
		log.Debug("Using always on sampler")
		return decorateSampler(tracesdk.AlwaysSample()), nil
	case ParentBasedAlwaysOffSampler:
		log.Debug("Using parent-based always off sampler")
		return decorateSampler(tracesdk.ParentBased(tracesdk.NeverSample())), nil
	case ParentBasedAlwaysOnSampler:
		log.Debug("Using parent-based always on sampler")
		return decorateSampler(tracesdk.ParentBased(tracesdk.AlwaysSample())), nil
	case ParentBasedTraceIDRatioSampler:
		f := env.GetOrDefault(TracesSamplerArgEV, "0.1")
		sampleFraction, err := strconv.ParseFloat(f, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trace ID ratio value %q: %w", f, err)
		}
		log.Debug(fmt.Sprintf("Using parent-based trace ID ratio sampler with fraction %f", sampleFraction))
		return decorateSampler(tracesdk.ParentBased(tracesdk.TraceIDRatioBased(sampleFraction))), nil
	case TraceIDRatioSampler:
		f := env.GetOrDefault(TracesSamplerArgEV, "0.1")
		sampleFraction, err := strconv.ParseFloat(f, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trace ID ratio value %q: %w", f, err)
		}
		log.Debug(fmt.Sprintf("Using trace ID ratio sampler with fraction %f", sampleFraction))
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
