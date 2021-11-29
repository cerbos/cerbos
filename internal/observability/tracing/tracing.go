// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/plugin/ochttp/propagation/tracecontext"
	octrace "go.opencensus.io/trace"
	"go.opencensus.io/trace/propagation"
	"go.opentelemetry.io/otel"
	ocbridge "go.opentelemetry.io/otel/bridge/opencensus"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/util"
)

var conf Conf

func Init(ctx context.Context) error {
	if err := config.GetSection(&conf); err != nil {
		return fmt.Errorf("failed to load tracing config: %w", err)
	}

	switch conf.Exporter {
	case jaegerExporter:
		return configureJaeger(ctx)
	case "":
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		return nil
	default:
		return fmt.Errorf("unknown exporter %q", conf.Exporter)
	}
}

func configureJaeger(ctx context.Context) error {
	var endpoint jaeger.EndpointOption
	if conf.Jaeger.AgentEndpoint != "" {
		agentHost, agentPort, err := net.SplitHostPort(conf.Jaeger.AgentEndpoint)
		if err != nil {
			return fmt.Errorf("failed to parse agent endpoint %q: %w", conf.Jaeger.AgentEndpoint, err)
		}

		endpoint = jaeger.WithAgentEndpoint(jaeger.WithAgentHost(agentHost), jaeger.WithAgentPort(agentPort))
	} else {
		endpoint = jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(conf.Jaeger.CollectorEndpoint))
	}

	exporter, err := jaeger.New(endpoint)
	if err != nil {
		return fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	return configureOtel(ctx, exporter)
}

func configureOtel(ctx context.Context, exporter tracesdk.SpanExporter) error {
	sampler := mkSampler(conf.SampleProbability)

	svcName := conf.Jaeger.ServiceName
	if svcName == "" {
		svcName = util.AppName
	}

	res, err := resource.New(context.Background(),
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(semconv.ServiceNameKey.String(svcName)),
		resource.WithProcessPID(),
		resource.WithHost(),
		resource.WithFromEnv())
	if err != nil {
		return fmt.Errorf("failed to initialize otel resource: %w", err)
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
	octrace.DefaultTracer = ocbridge.NewTracer(traceProvider.Tracer("cerbos"))

	go func() {
		<-ctx.Done()
		// TODO (cell) Add hook to make the server wait until the trace provider shuts down cleanly.

		if err := traceProvider.Shutdown(context.TODO()); err != nil {
			zap.L().Warn("Failed to cleanly shutdown trace exporter", zap.Error(err))
		}
	}()

	return nil
}

func mkSampler(probability float64) tracesdk.Sampler {
	if probability == 0.0 {
		return tracesdk.NeverSample()
	}

	return sampler{s: tracesdk.ParentBased(tracesdk.TraceIDRatioBased(conf.SampleProbability))}
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

func HTTPHandler(handler http.Handler) http.Handler {
	var prop propagation.HTTPFormat
	if conf.PropagationFormat == propagationW3CTraceContext {
		prop = &tracecontext.HTTPFormat{}
	}

	return &ochttp.Handler{
		Handler:     handler,
		Propagation: prop,
	}
}

func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return otel.Tracer("cerbos.dev/cerbos").Start(ctx, name)
}

func MarkFailed(span trace.Span, code int, err error) {
	if err != nil {
		span.RecordError(err)
	}

	c, desc := semconv.SpanStatusFromHTTPStatusCode(code)
	span.SetStatus(c, desc)
}

type otelErrHandler func(err error)

func (o otelErrHandler) Handle(err error) {
	o(err)
}
