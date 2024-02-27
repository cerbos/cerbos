// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerboshub

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/config"
	badgerv4 "github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/ristretto/z"
	"go.uber.org/zap"
)

const (
	goroutineResetThreshold = 1 << 16

	Backend = "cerboshub"
)

var (
	SyncStatusPrefix   = []byte("bs") // "b" for contiguity with audit log keys in LSM, "s" because "sync"
	AccessSyncPrefix   = []byte("bsacc")
	DecisionSyncPrefix = []byte("bsdec")
)

func init() {
	audit.RegisterBackend(Backend, func(_ context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read cerboshub audit log configuration: %w", err)
		}

		syncer := NewIngestSyncer()

		return NewLog(conf, decisionFilter, syncer)
	})
}

type Log struct {
	*local.Log
	logger  *zap.Logger
	syncer  IngestSyncer
	ticker  *time.Ticker
	trigger chan local.TriggerSignal
}

func NewLog(conf *Conf, decisionFilter audit.DecisionLogEntryFilter, syncer IngestSyncer) (*Log, error) {
	log, err := local.NewLog(&conf.Conf, decisionFilter)
	if err != nil {
		return nil, err
	}

	logger := zap.L().Named("auditlog").With(zap.String("backend", Backend))

	maxBatchSize := int(conf.Ingest.BatchSize)
	flushInterval := conf.Ingest.FlushInterval
	numGo := int(conf.Ingest.NumGoRoutines)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	l := &Log{
		Log:     log,
		logger:  logger,
		syncer:  syncer,
		ticker:  ticker,
		trigger: make(chan local.TriggerSignal, 1),
	}

	go local.StartTriggerLoop(ticker, l.trigger, l.StopChan)

	l.Wg.Add(1)
	go l.batchSyncer(maxBatchSize, numGo, flushInterval)

	return l, nil
}

func (l *Log) WriteAccessLogEntry(ctx context.Context, record audit.AccessLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	if err := l.Log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
		return rec, nil
	}); err != nil {
		return err
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	key := local.GenKey(AccessSyncPrefix, callID)

	return l.Write(ctx, key, nil)
}

func (l *Log) WriteDecisionLogEntry(ctx context.Context, record audit.DecisionLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	if err := l.Log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		return rec, nil
	}); err != nil {
		return err
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	key := local.GenKey(DecisionSyncPrefix, callID)

	return l.Write(ctx, key, nil)
}

func (l *Log) batchSyncer(maxBatchSize, numGo int, flushInterval time.Duration) {
	logger := l.logger.With(zap.String("component", "ingest-syncer"))

	for i := 0; i < goroutineResetThreshold; i++ {
		select {
		case <-l.StopChan:
			l.Wg.Done()
			return
		case sig := <-l.trigger:
			// BadgerDB transactions work with snapshot isolation so we only take a view of the DB.
			// Subsequent writes aren't blocked.
			stream := l.Db.NewStream()
			stream.NumGo = numGo
			stream.Prefix = SyncStatusPrefix

			stream.Send = func(buf *z.Buffer) error {
				kvList, err := badgerv4.BufferToKVList(buf)
				if err != nil {
					return err
				}

				keys := make([][]byte, len(kvList.Kv))
				for i, kv := range kvList.Kv {
					keys[i] = kv.Key
				}

				for i := 0; i < len(keys); i += maxBatchSize {
					end := i + maxBatchSize
					if end > len(keys) {
						end = len(keys)
					}
					batch := keys[i:end]

					{
						wb := l.Db.NewWriteBatch()
						defer wb.Cancel()

						if err := l.syncer.Sync(context.Background(), batch); err != nil {
							return err
						}

						if err := l.deleteKeys(wb, batch); err != nil {
							return err
						}
					}
				}

				return nil
			}

			newFlushInterval := flushInterval
			if err := stream.Orchestrate(context.Background()); err != nil {
				var ingestErr ErrIngestBackoff
				if errors.As(err, &ingestErr) {
					logger.Warn("svc-ingest issued backoff", zap.Error(err))
					newFlushInterval = ingestErr.Backoff
				} else {
					logger.Warn("Failed sync", zap.Error(err))
				}
			}

			l.ticker.Reset(newFlushInterval)

			if sig.ResponseCh != nil {
				sig.ResponseCh <- struct{}{}
			}
		}
	}

	// restart the goroutine with a fresh stack
	go l.batchSyncer(maxBatchSize, numGo, flushInterval)
}

func (l *Log) deleteKeys(wb *badgerv4.WriteBatch, keys [][]byte) error {
	for _, k := range keys {
		if err := wb.Delete(k); err != nil {
			if errors.Is(err, badgerv4.ErrDiscardedTxn) {
				wb = l.Db.NewWriteBatch()
				_ = wb.Delete(k)
			} else {
				return err
			}
		}
	}

	return wb.Flush()
}

// ForceSync forces a sync operation and blocks until completion.
func (l *Log) ForceSync() {
	l.Log.ForceSync()

	done := make(chan struct{}, 1)
	l.trigger <- local.TriggerSignal{
		ResponseCh: done,
	}
	<-done
}

func (l *Log) Backend() string {
	return Backend
}
