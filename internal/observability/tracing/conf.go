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
	SampleProbability float64 `yaml:"sampleProbability"`
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
