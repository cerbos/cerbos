package tracing

import (
	"fmt"
	"strings"

	"contrib.go.opencensus.io/exporter/jaeger"
	"go.opencensus.io/trace"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/util"
)

func Init() error {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return fmt.Errorf("failed to load tracing config: %w", err)
	}

	if conf.Exporter == "" || conf.SampleProbability == 0.0 {
		trace.ApplyConfig(trace.Config{DefaultSampler: trace.NeverSample()})
		return nil
	}

	if conf.Exporter == jaegerExporter {
		svcName := conf.Jaeger.ServiceName
		if svcName == "" {
			svcName = util.AppName
		}

		opts := jaeger.Options{
			Process: jaeger.Process{ServiceName: svcName},
		}

		if conf.Jaeger.AgentEndpoint != "" {
			opts.AgentEndpoint = conf.Jaeger.AgentEndpoint
		} else {
			opts.CollectorEndpoint = conf.Jaeger.CollectorEndpoint
		}

		exporter, err := jaeger.NewExporter(opts)
		if err != nil {
			return fmt.Errorf("failed to create Jaeger exporter: %w", err)
		}

		trace.ApplyConfig(trace.Config{DefaultSampler: mkSampler(conf.SampleProbability)})
		trace.RegisterExporter(exporter)

		return nil
	}

	return nil
}

func mkSampler(probability float64) trace.Sampler {
	ps := trace.ProbabilitySampler(probability)

	return func(params trace.SamplingParameters) trace.SamplingDecision {
		if strings.HasPrefix(params.Name, "grpc.health") {
			return trace.SamplingDecision{Sample: false}
		}

		return ps(params)
	}
}

func MarkFailed(span *trace.Span, code int32, msg string, err error) {
	span.AddAttributes(trace.StringAttribute("error_message", err.Error()))
	span.SetStatus(trace.Status{Code: code, Message: msg})
}
