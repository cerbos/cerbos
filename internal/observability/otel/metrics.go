// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/util"
)

const shutdownTimeout = 5 * time.Second

func InitMetrics(ctx context.Context, env Env) (func() error, error) {
	var exporter sdkmetric.Reader
	var err error

	exporterKind := env.GetOrDefault(MetricsExporterEV, PrometheusExporter)
	switch exporterKind {
	case NoneExporter:
		return noopCloseFn, nil
	case OTLPExporter:
		if _, endpointDefined := env.Get(MetricsEndpointEV); !endpointDefined {
			zap.L().Named("otel").Warn("Disabling OTLP metrics because neither OTEL_EXPORTER_OTLP_ENDPOINT nor OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is defined")
			return noopCloseFn, nil
		}
		exporter, err = createOTLPMetricsExporter(ctx, env)
	case PrometheusExporter:
		exporter, err = otelprom.New(otelprom.WithoutTargetInfo(), otelprom.WithoutScopeInfo())
	default:
		return nil, fmt.Errorf("unknown metrics exporter %q", exporterKind)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create %s metrics exporter: %w", exporterKind, err)
	}

	res, err := newResource(ctx, env.GetOrDefault(ServiceNameEV, util.AppName))
	if err != nil {
		return nil, fmt.Errorf("failed to create Otel resource: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithView(dropHighCardinalityLabels()),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(provider)

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		return exporter.Shutdown(ctx)
	}, nil
}

func createOTLPMetricsExporter(ctx context.Context, env Env) (sdkmetric.Reader, error) {
	var exporter sdkmetric.Exporter
	var err error

	protocol := env.GetOrDefault(MetricsProtocolEV, GRPCProtocol)
	switch protocol {
	case GRPCProtocol:
		exporter, err = otlpmetricgrpc.New(ctx)
	case HTTPProtobufProtocol:
		exporter, err = otlpmetrichttp.New(ctx)
	default:
		err = fmt.Errorf("unsupported metrics exporter protocol %q", protocol)
	}

	if err != nil {
		return nil, err
	}

	intervalVal := env.GetOrDefault(MetricsExportIntervalEV, "60000")
	interval, err := strconv.Atoi(intervalVal)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics export interval %q: %w", intervalVal, err)
	}

	timeoutVal := env.GetOrDefault(MetricsExportTimeoutEV, "30000")
	timeout, err := strconv.Atoi(timeoutVal)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics export timeout %q: %w", timeoutVal, err)
	}

	zap.L().Named("otel").Info(fmt.Sprintf("Initialized OTLP metrics exporter with protocol=%s, interval=%d, timeout=%d", protocol, interval, timeout))

	return sdkmetric.NewPeriodicReader(
		exporter,
		sdkmetric.WithInterval(time.Duration(interval)*time.Millisecond),
		sdkmetric.WithTimeout(time.Duration(timeout)*time.Millisecond),
	), nil
}

func dropHighCardinalityLabels() sdkmetric.View {
	attributeFilter := func(attr attribute.KeyValue) bool {
		attrStr := string(attr.Key)
		switch {
		case attrStr == "client.address":
			return false
		case attrStr == "user_agent.original":
			return false
		case attrStr == "network.protocol.version":
			return false
		case attrStr == "url.scheme":
			return false
		case strings.HasPrefix(attrStr, "server."):
			return false
		case strings.HasPrefix(attrStr, "network.peer."):
			return false
		}
		return true
	}

	return sdkmetric.NewView(
		sdkmetric.Instrument{
			Name: "*",
		},
		sdkmetric.Stream{
			AttributeFilter: attributeFilter,
		},
	)
}
