// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"errors"
	"fmt"
)

const (
	confKey        = "tracing"
	jaegerExporter = "jaeger"
	otlpExporter   = "otlp"
)

var (
	errJaegerConfigUndefined   = errors.New("jaeger configuration is empty")
	errJaegerEndpointUndefined = errors.New("jaeger endpoint undefined")

	errOTLPConfigUndefined   = errors.New("otlp configuration is empty")
	errOTLPEndpointUndefined = errors.New("otlp endpoint undefined")
)

// Conf is optional configuration for tracing.
type Conf struct {
	// ServiceName is the name of the service reproted to the exporter.
	ServiceName *string
	// Jaeger configures the Jaeger exporter.
	Jaeger *JaegerConf `yaml:"jaeger"`
	// OTLP configures the OpenTelemetry exporter.
	OTLP *OTLPConf `yaml:"otlp"`
	// [Deprecated] PropagationFormat is no longer used. Traces in trace-context, baggage, or b3 formats are automatically detected and propagated.
	PropagationFormat string `yaml:"propagationFormat" conf:",ignore"`
	// Exporter is the type of trace exporter to use.
	Exporter string `yaml:"exporter" conf:",example=jaeger"`
	// SampleProbability is the probability of sampling expressed as a number between 0 and 1.
	SampleProbability float64 `yaml:"sampleProbability" conf:",example=0.1"`
}

type JaegerConf struct {
	// [Deprecated] Use top level ServiceName config. ServiceName is the name of the service to report to Jaeger.
	ServiceName string `yaml:"serviceName" conf:",example=cerbos"`
	// AgentEndpoint is the Jaeger agent endpoint to report to.
	AgentEndpoint string `yaml:"agentEndpoint" conf:",example=\"localhost:6831\""`
	// CollectorEndpoint is the Jaeger collector endpoint to report to.
	CollectorEndpoint string `yaml:"collectorEndpoint" conf:",example=\"http://localhost:14268/api/traces\""`
}

type OTLPConf struct {
	// CollectorEndpoint is the Jaeger collector endpoint to report to.
	CollectorEndpoint string `yaml:"collectorEndpoint" conf:",example=\"otel:4317\""`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) Validate() error {
	switch c.Exporter {
	case "":
		return nil

	case jaegerExporter:
		if c.Jaeger == nil {
			return errJaegerConfigUndefined
		}
		if c.Jaeger.AgentEndpoint == "" && c.Jaeger.CollectorEndpoint == "" {
			return errJaegerEndpointUndefined
		}
		return nil

	case otlpExporter:
		if c.OTLP == nil {
			return errOTLPConfigUndefined
		}
		if c.OTLP.CollectorEndpoint == "" {
			return errOTLPEndpointUndefined
		}
		return nil

	default:
		return fmt.Errorf("unknown trace exporter %s", c.Exporter)
	}
}
