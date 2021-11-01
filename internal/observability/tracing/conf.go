// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./../../gen/gendocsfromconf.go

package tracing

import (
	"errors"
	"fmt"
)

const (
	confKey        = "tracing"
	jaegerExporter = "jaeger"
)

var (
	errJaegerConfigUndefined   = errors.New("jaeger configuration is empty")
	errJaegerEndpointUndefined = errors.New("jaeger endpoint undefined")
)

// Conf holds the tracing configuration.
type Conf struct {
	// SampleProbability is the probability of sampling expressed as a number between 0 and 1.
	SampleProbability float64 `yaml:"sampleProbability" conf:"optional"`
	// Exporter is the type of trace exporter to use.
	Exporter string `yaml:"exporter" conf:"optional"`
	// Jaeger configures the Jaeger exporter.
	Jaeger *JaegerConf `yaml:"jaeger" conf:"optional"`
}

type JaegerConf struct {
	// ServiceName is the name of the service to report to Jaeger.
	ServiceName string `yaml:"serviceName" conf:"optional"`
	// AgentEndpoint is the Jaeger agent endpoint to report to.
	AgentEndpoint string `yaml:"agentEndpoint" conf:"optional"`
	// CollectorEndpoint is the Jaeger collector endpoint to report to.
	CollectorEndpoint string `yaml:"collectorEndpoint" conf:"optional"`
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
	default:
		return fmt.Errorf("unknown trace exporter %s", c.Exporter)
	}
}
