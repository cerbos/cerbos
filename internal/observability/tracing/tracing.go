// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	otelsdk "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger" //nolint:staticcheck
	"go.opentelemetry.io/otel/semconv/v1.13.0/httpconv"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/otel"
	"github.com/cerbos/cerbos/internal/util"
)

var conf Conf

func Init(ctx context.Context) (func() error, error) {
	if err := config.GetSection(&conf); err != nil {
		return nil, fmt.Errorf("failed to load tracing config: %w", err)
	}

	return InitFromConf(ctx, conf)
}

func InitFromConf(ctx context.Context, conf Conf) (func() error, error) {
	switch conf.Exporter {
	case jaegerExporter:
		warnConfigDeprecation(true)
		return configureJaeger(ctx)
	case otlpExporter:
		warnConfigDeprecation(false)
		return configureOTLP(ctx)
	default:
		return otel.InitTraces(ctx, otel.Env(os.LookupEnv))
	}
}

func warnConfigDeprecation(jaeger bool) {
	log := zap.L().Named("tracing")
	if jaeger {
		log.Warn("[DEPRECATED CONFIG] Jaeger trace exporter is deprecated in favour of OTLP. Next version of Cerbos will drop support for jaeger exporter. Please refer to https://docs.cerbos.dev/cerbos/latest/configuration/tracing#migration for migration instructions.")
	} else {
		log.Warn("[DEPRECATED CONFIG] File-based tracing configuration is deprecated in favour of configuration through OpenTelemetry environment variables. Next version of Cerbos will drop support for configuring tracing via Cerbos configuration file. Please refer to https://docs.cerbos.dev/cerbos/latest/configuration/tracing#migration for migration instructions.")
	}
}

func configureJaeger(ctx context.Context) (func() error, error) {
	var endpoint jaeger.EndpointOption
	if conf.Jaeger.AgentEndpoint != "" {
		agentHost, agentPort, err := net.SplitHostPort(conf.Jaeger.AgentEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent endpoint %q: %w", conf.Jaeger.AgentEndpoint, err)
		}

		endpoint = jaeger.WithAgentEndpoint(jaeger.WithAgentHost(agentHost), jaeger.WithAgentPort(agentPort))
	} else {
		endpoint = jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(conf.Jaeger.CollectorEndpoint))
	}

	exporter, err := jaeger.New(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	svcName := conf.ServiceName
	if svcName == nil {
		if conf.Jaeger.ServiceName != "" {
			svcName = &conf.Jaeger.ServiceName
		} else {
			svcName = &util.AppName
		}
	}

	envMap := map[string]string{
		otel.ServiceNameEV.Name:      *svcName,
		otel.TracesSamplerEV.Name:    otel.ParentBasedTraceIDRatioSampler,
		otel.TracesSamplerArgEV.Name: fmt.Sprintf("%0.2f", conf.SampleProbability),
	}

	env := func(key string) (string, bool) {
		// TODO: Give precedence to actual environment variables when the tracing configuration is deprecated.
		v, ok := envMap[key]
		if ok {
			return v, ok
		}

		return os.LookupEnv(key)
	}

	return otel.InitTracesWithExporter(ctx, otel.Env(env), exporter)
}

func configureOTLP(ctx context.Context) (func() error, error) {
	svcName := conf.ServiceName
	if svcName == nil {
		if conf.Jaeger.ServiceName != "" {
			svcName = &conf.Jaeger.ServiceName
		} else {
			svcName = &util.AppName
		}
	}

	envMap := map[string]string{
		otel.ServiceNameEV.Name:            *svcName,
		otel.TracesSamplerEV.Name:          otel.ParentBasedTraceIDRatioSampler,
		otel.TracesSamplerArgEV.Name:       fmt.Sprintf("%0.2f", conf.SampleProbability),
		otel.TracesEndpointEV.Name:         conf.OTLP.CollectorEndpoint,
		otel.TracesEndpointInsecureEV.Name: "true",
	}

	env := func(key string) (string, bool) {
		// TODO: Give precedence to actual environment variables when the tracing configuration is deprecated.
		v, ok := envMap[key]
		if ok {
			return v, ok
		}

		return os.LookupEnv(key)
	}

	return otel.InitTraces(ctx, otel.Env(env))
}

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
