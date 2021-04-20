package engine

import (
	"context"
	"errors"
	"time"

	"go.opencensus.io/stats"
	"go.opencensus.io/tag"

	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	"github.com/cerbos/cerbos/internal/observability/metrics"
)

func measureUpdateLatency(updateType string, updateOp func() error) error {
	startTime := time.Now()
	err := updateOp()
	latencyMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	status := "success"
	if err != nil {
		status = "failure"
	}

	_ = stats.RecordWithTags(context.Background(),
		[]tag.Mutator{
			tag.Upsert(metrics.KeyEngineUpdateStatus, status),
			tag.Upsert(metrics.KeyEngineUpdateType, updateType),
		},
		metrics.EngineUpdateLatency.M(latencyMs),
	)

	return err
}

func measureCheckLatency(checkFn func() (*CheckResult, error)) (*CheckResult, error) {
	startTime := time.Now()
	result, err := checkFn()
	evalDuration := time.Since(startTime)

	result.setEvaluationDuration(evalDuration)
	latencyMs := float64(evalDuration) / float64(time.Millisecond)

	status := "success"
	if err != nil {
		if errors.Is(err, ErrNoPoliciesMatched) {
			status = "no_policies_matched"
		} else {
			status = "failure"
		}
	}

	decision := result.Effect.String()

	_ = stats.RecordWithTags(context.Background(),
		[]tag.Mutator{
			tag.Upsert(metrics.KeyEngineDecisionStatus, status),
			tag.Upsert(metrics.KeyEngineDecisionEffect, decision),
		},
		metrics.EngineCheckLatency.M(latencyMs),
	)

	return result, err
}

func measureCheckResourceBatchLatency(checkFn func() (*responsev1.CheckResourceBatchResponse, error)) (*responsev1.CheckResourceBatchResponse, error) {
	startTime := time.Now()
	resp, err := checkFn()
	latencyMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	status := "success"
	if err != nil {
		if errors.Is(err, ErrNoPoliciesMatched) {
			status = "no_policies_matched"
		} else {
			status = "failure"
		}
	}

	_ = stats.RecordWithTags(context.Background(),
		[]tag.Mutator{
			tag.Upsert(metrics.KeyEngineDecisionStatus, status),
		},
		metrics.EngineCheckResourceBatchLatency.M(latencyMs),
	)

	return resp, err
}
