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

const (
	statusFailure           = "failure"
	statusNoPoliciesMatched = "no_policies_matched"
	statusSuccess           = "success"
)

func measureUpdateLatency(updateType string, updateOp func() error) error {
	startTime := time.Now()
	err := updateOp()
	latencyMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	status := statusSuccess
	if err != nil {
		status = statusFailure
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

	status := statusSuccess
	if err != nil {
		if errors.Is(err, ErrNoPoliciesMatched) {
			status = statusNoPoliciesMatched
		} else {
			status = statusFailure
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

	status := statusSuccess
	if err != nil {
		if errors.Is(err, ErrNoPoliciesMatched) {
			status = statusNoPoliciesMatched
		} else {
			status = statusFailure
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
