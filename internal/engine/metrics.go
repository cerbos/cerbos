// Copyright 2021 Zenauth Ltd.

package engine

import (
	"context"
	"time"

	"go.opencensus.io/stats"
	"go.opencensus.io/tag"

	enginev1 "github.com/cerbos/cerbos/internal/genpb/engine/v1"
	"github.com/cerbos/cerbos/internal/observability/metrics"
)

const (
	statusFailure = "failure"
	statusSuccess = "success"
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

func measureCheckLatency(batchSize int, checkFn func() ([]*enginev1.CheckOutput, error)) ([]*enginev1.CheckOutput, error) {
	startTime := time.Now()
	result, err := checkFn()

	latencyMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	status := statusSuccess
	if err != nil {
		status = statusFailure
	}

	_ = stats.RecordWithTags(context.Background(),
		[]tag.Mutator{
			tag.Upsert(metrics.KeyEngineDecisionStatus, status),
		},
		metrics.EngineCheckLatency.M(latencyMs),
		metrics.EngineCheckBatchSize.M(int64(batchSize)),
	)

	return result, err
}
