// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/cenkalti/backoff/v5"
	"github.com/cerbos/cerbos/internal/hub"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/logcap"
)

const (
	initialBackoffInterval     = 1 * time.Second
	backoffRandomizationFactor = 0.5
	backoffMultiplier          = 1.5
	maxBackoffInterval         = 2 * time.Minute
)

type ErrIngestBackoff struct {
	underlying error
	Backoff    time.Duration
}

func (e ErrIngestBackoff) Error() string {
	return e.underlying.Error()
}

type IngestSyncer interface {
	Sync(context.Context, *logsv1.IngestBatch) error
}

type wrappedBackOff struct {
	backoff.BackOff
	mu sync.Mutex
}

func (exp *wrappedBackOff) NextBackOff() time.Duration {
	exp.mu.Lock()
	defer exp.mu.Unlock()

	return exp.BackOff.NextBackOff()
}

func (exp *wrappedBackOff) Reset() {
	exp.mu.Lock()
	defer exp.mu.Unlock()

	exp.BackOff.Reset()
}

type Impl struct {
	client *logcap.Client
	log    *zap.Logger
	wbo    *wrappedBackOff
}

func NewIngestSyncer(logger *zap.Logger) (*Impl, error) {
	hubInstance, err := hub.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to establish Cerbos Hub connection: %w", err)
	}

	client, err := hubInstance.LogCapClient()
	if err != nil {
		return nil, err
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = initialBackoffInterval
	bo.RandomizationFactor = backoffRandomizationFactor
	bo.Multiplier = backoffMultiplier
	bo.MaxInterval = maxBackoffInterval
	bo.Reset()

	return &Impl{
		client: client,
		log:    logger,
		wbo: &wrappedBackOff{
			BackOff: bo,
		},
	}, nil
}

func (i *Impl) Sync(ctx context.Context, batch *logsv1.IngestBatch) error {
	if len(batch.GetEntries()) == 0 {
		return nil
	}

	resp, err := i.client.Ingest(ctx, batch)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		i.log.Error("Failed to sync batch", zap.Error(err))

		// Hard failure: use exponential backoff
		duration := i.wbo.NextBackOff()
		if duration == backoff.Stop {
			return err
		}
		return ErrIngestBackoff{underlying: err, Backoff: duration}
	}

	i.wbo.Reset()

	if resp > 0 {
		return ErrIngestBackoff{underlying: errors.New("server requested backoff before retrying"), Backoff: resp}
	}

	return nil
}
