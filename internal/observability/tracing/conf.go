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

// Conf holds the tracing configuration.
type Conf struct {
	// SampleProbability is the probability of sampling expressed as a number between 0 and 1.
	SampleProbability float64 `yaml:"sampleProbability"`
	// PropagationFormat is the trace propagation format to use. Valid values are w3c-tracecontext or b3.
	PropagationFormat string `yaml:"propagationFormat"`
	// Exporter is the type of trace exporter to use.
	Exporter string `yaml:"exporter"`
	// Jaeger configures the Jaeger exporter.
	Jaeger *JaegerConf `yaml:"jaeger"`
}

type JaegerConf struct {
	// ServiceName is the name of the service to report to Jaeger.
	ServiceName string `yaml:"serviceName"`
	// AgentEndpoint is the Jaeger agent endpoint to report to.
	AgentEndpoint string `yaml:"agentEndpoint"`
	// CollectorEndpoint is the Jaeger collector endpoint to report to.
	CollectorEndpoint string `yaml:"collectorEndpoint"`
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
