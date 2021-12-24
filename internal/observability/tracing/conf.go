// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"errors"
	"fmt"
)

const (
	confKey                    = "tracing"
	jaegerExporter             = "jaeger"
	propagationW3CTraceContext = "w3c-tracecontext"
	propagationB3              = "b3"
)

var (
	errJaegerConfigUndefined   = errors.New("jaeger configuration is empty")
	errJaegerEndpointUndefined = errors.New("jaeger endpoint undefined")
)

// Conf is optional configuration for tracing.
type Conf struct {
	// Jaeger configures the Jaeger exporter.
	Jaeger *JaegerConf `yaml:"jaeger"`
	// PropagationFormat is the trace propagation format to use. Valid values are w3c-tracecontext or b3.
	PropagationFormat string `yaml:"propagationFormat" conf:",ignore"`
	// Exporter is the type of trace exporter to use.
	Exporter string `yaml:"exporter" conf:",example=jaeger"`
	// SampleProbability is the probability of sampling expressed as a number between 0 and 1.
	SampleProbability float64 `yaml:"sampleProbability" conf:",example=0.1"`
}

type JaegerConf struct {
	// ServiceName is the name of the service to report to Jaeger.
	ServiceName string `yaml:"serviceName" conf:",example=cerbos"`
	// AgentEndpoint is the Jaeger agent endpoint to report to.
	AgentEndpoint string `yaml:"agentEndpoint" conf:",example=\"localhost:6831\""`
	// CollectorEndpoint is the Jaeger collector endpoint to report to.
	CollectorEndpoint string `yaml:"collectorEndpoint" conf:",example=\"http://localhost:14268\""`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.PropagationFormat = propagationW3CTraceContext
}

func (c *Conf) Validate() error {
	if c.PropagationFormat != propagationW3CTraceContext && c.PropagationFormat != propagationB3 {
		return fmt.Errorf("unsupported propagation format %q: valid values are %q or %q", c.PropagationFormat, propagationW3CTraceContext, propagationB3)
	}

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
	default:
		return fmt.Errorf("unknown trace exporter %s", c.Exporter)
	}
}
