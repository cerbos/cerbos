// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/hub"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/logcap"
)

const DefaultErrorBackoff = 30 * time.Second

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

type Impl struct {
	client *logcap.Client
	log    *zap.Logger
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

	return &Impl{
		client: client,
		log:    logger,
	}, nil
}

func (i *Impl) Sync(ctx context.Context, batch *logsv1.IngestBatch) (err error) {
	if len(batch.GetEntries()) > 0 {
		var backoff time.Duration
		defer func() {
			// if the server responds with a backoff, return it regardless of whether an error exists
			if backoff != 0 {
				err = ErrIngestBackoff{
					underlying: err,
					Backoff:    backoff,
				}
			} else if err != nil {
				// Apply fixed default backoff for severe failures (typically network issues)
				// where the server couldn't communicate a specific backoff duration.
				// Using a conservative fixed backoff rather than exponential backoff as
				// these errors are expected to be transient network issues and retrying
				// too aggressively could exacerbate the problem (and because an exponential
				// backoff here feels entirely overkill).
				err = ErrIngestBackoff{
					underlying: err,
					Backoff:    DefaultErrorBackoff,
				}
			}
		}()

		backoff, err = i.client.Ingest(ctx, batch)
		if err != nil {
			i.log.Error("Failed to sync batch", zap.Error(err))
			return
		}
	}

	return
}
