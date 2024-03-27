// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/metric"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/storage"
)

// instrument wraps the given source to produce metrics.
func instrument(name string, source storage.BinaryStore) storage.BinaryStore {
	return instrumentedSource{name: name, source: source}
}

// instrumentedSource is a source that measures the time taken by each operation.
type instrumentedSource struct {
	source storage.BinaryStore
	name   string
}

func (instrumentedSource) Driver() string {
	return DriverName
}

func (is instrumentedSource) ListPoliciesMetadata(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.ListPoliciesMetadataResponse_Metadata, error) {
	return measureBinaryOp(ctx, is.name, "ListPoliciesMetadata", func(ctx context.Context) (map[string]*responsev1.ListPoliciesMetadataResponse_Metadata, error) {
		return is.source.ListPoliciesMetadata(ctx, params)
	})
}

func (is instrumentedSource) ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	return measureBinaryOp(ctx, is.name, "ListPolicyIDs", func(ctx context.Context) ([]string, error) {
		return is.source.ListPolicyIDs(ctx, params)
	})
}

func (is instrumentedSource) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return measureBinaryOp(ctx, is.name, "ListSchemaIDs", func(ctx context.Context) ([]string, error) {
		return is.source.ListSchemaIDs(ctx)
	})
}

func (is instrumentedSource) LoadSchema(ctx context.Context, id string) (io.ReadCloser, error) {
	return measureBinaryOp(ctx, is.name, "LoadSchema", func(ctx context.Context) (io.ReadCloser, error) {
		return is.source.LoadSchema(ctx, id)
	})
}

func (is instrumentedSource) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	return measureBinaryOp(ctx, is.name, "GetFirstMatch", func(ctx context.Context) (*runtimev1.RunnablePolicySet, error) {
		return is.source.GetFirstMatch(ctx, candidates)
	})
}

func (is instrumentedSource) Reload(ctx context.Context) error {
	if r, ok := is.source.(storage.Reloadable); ok {
		return r.Reload(ctx)
	}
	return nil
}

func (is instrumentedSource) Close() error {
	if c, ok := is.source.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (is instrumentedSource) SourceKind() string {
	if s, ok := is.source.(Source); ok {
		return s.SourceKind()
	}

	return "unknown"
}

func measureBinaryOp[T any](ctx context.Context, source, opName string, op func(context.Context) (T, error)) (T, error) {
	startTime := time.Now()
	result, err := withTrace(ctx, source, opName, op)
	latencyMs := metrics.TotalTimeMS(startTime)

	status := "success"
	if err != nil {
		status = "failure"
	}

	metrics.BundleStoreLatency().Record(context.Background(), latencyMs, metric.WithAttributes(
		metrics.SourceKey(source),
		metrics.OpKey(opName),
		metrics.StatusKey(status),
	))

	return result, err
}

func withTrace[T any](ctx context.Context, source, opName string, op func(context.Context) (T, error)) (T, error) {
	newCtx, span := tracing.StartSpan(ctx, "bundle."+opName)
	span.SetAttributes(tracing.BundleSource(source))

	result, err := op(newCtx)
	if err != nil {
		tracing.MarkFailed(span, http.StatusInternalServerError, err)
	}

	span.End()
	return result, err
}
