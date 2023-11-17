// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"errors"
	"fmt"
	"os"

	"go.uber.org/multierr"

	"github.com/cerbos/cerbos/internal/util"
)

const confKey = "otel"

var traceCollectorEnvVars = []string{
	"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
}

type Conf struct {
	// ServiceName is the name of the service reported by OpenTelemetry.
	ServiceName string `yaml:"serviceName" conf:",example=cerbos"`
	// Tracing configures the OpenTelemetry traces.
	Tracing *TracingConf `yaml:"tracing"`
}

type TracingConf struct {
	// SampleProbability is the probability of sampling expressed as a number between 0 and 1.
	SampleProbability float64 `yaml:"sampleProbability" conf:",example=0.1"`
	// CollectorProtocol is the network protocol to use for communicating with the OTLP collector. Defaults to grpc.
	CollectorProtocol string `yaml:"collectorProtocol" conf:",example=grpc"`
	// CollectorEndpoint is the address of the OTLP collector.
	CollectorEndpoint string `yaml:"collectorEndpoint" conf:",example=${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}"`
}

func (tc *TracingConf) Validate() (outErr error) {
	if tc == nil || tc.SampleProbability == 0.0 {
		return nil
	}

	if tc.CollectorProtocol != "grpc" && tc.CollectorProtocol != "http" {
		outErr = multierr.Append(outErr, fmt.Errorf("unknown otel.tracing.collectorProtocol %q: must be one of grpc or http", tc.CollectorProtocol))
	}

	if tc.CollectorEndpoint == "" {
		endpointDefined := false
		for _, v := range traceCollectorEnvVars {
			if os.Getenv(v) != "" {
				endpointDefined = true
				break
			}
		}

		if !endpointDefined {
			outErr = multierr.Append(outErr, errors.New("otel.tracing.collectorEndpoint must be defined"))
		}
	}

	return outErr
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.ServiceName = util.AppName
}

func (c *Conf) Validate() error {
	return c.Tracing.Validate()
}
