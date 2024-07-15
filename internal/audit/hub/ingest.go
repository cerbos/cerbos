// Copyright 2021-2024 Zenauth Ltd.
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

func (i *Impl) Sync(ctx context.Context, batch *logsv1.IngestBatch) error {
	if err := i.client.Ingest(ctx, batch); err != nil {
		i.log.Error("Failed to sync batch", zap.Error(err))
		return err
	}

	return nil
}
