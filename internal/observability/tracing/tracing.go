// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"strings"

	"contrib.go.opencensus.io/exporter/jaeger"
	"go.opencensus.io/trace"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/util"
)

var conf Conf

func Init() error {
	if err := config.GetSection(&conf); err != nil {
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

		trace.ApplyConfig(trace.Config{DefaultSampler: trace.ProbabilitySampler(conf.SampleProbability)})
		trace.RegisterExporter(exporter)

		return nil
	}

	return nil
}

// StartOptions returns the options for tracing http and gRPC calls.
func StartOptions() trace.StartOptions {
	opt := trace.StartOptions{
		SpanKind: trace.SpanKindServer,
	}

	if conf.Exporter == "" || conf.SampleProbability == 0.0 {
		opt.Sampler = trace.NeverSample()
	} else {
		opt.Sampler = mkSampler(conf.SampleProbability)
	}

	return opt
}

func mkSampler(probability float64) trace.Sampler {
	ps := trace.ProbabilitySampler(probability)

	return func(params trace.SamplingParameters) trace.SamplingDecision {
		switch {
		case strings.HasPrefix(params.Name, "grpc."):
			return trace.SamplingDecision{Sample: false}
		case strings.HasPrefix(params.Name, "cerbos.svc.v1.CerbosPlaygroundService."):
			return trace.SamplingDecision{Sample: false}
		case strings.HasPrefix(params.Name, "cerbos.svc.v1.CerbosAdminService."):
			return trace.SamplingDecision{Sample: false}
		case strings.HasPrefix(params.Name, "/api/playground/"):
			return trace.SamplingDecision{Sample: false}
		default:
			return ps(params)
		}
	}
}

func StartSpan(ctx context.Context, name string) (context.Context, *trace.Span) {
	return trace.StartSpan(ctx, fmt.Sprintf("cerbos.dev/%s", name))
}

func MarkFailed(span *trace.Span, code int32, msg string, err error) {
	span.AddAttributes(trace.StringAttribute("error_message", err.Error()))
	span.SetStatus(trace.Status{Code: code, Message: msg})
}
