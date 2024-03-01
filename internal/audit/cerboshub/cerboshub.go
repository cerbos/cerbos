// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerboshub

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	Backend = "cerboshub"
)

var (
	SyncStatusPrefix   = []byte("bs") // "b" for contiguity with audit log keys in LSM, "s" because "sync"
	AccessSyncPrefix   = []byte("bsacc")
	DecisionSyncPrefix = []byte("bsdec")
)

func init() {
	audit.RegisterBackend(Backend, func(_ context.Context, confW *config.Wrapper, _ audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read cerboshub audit log configuration: %w", err)
		}

		// syncer := NewIngestSyncer()
		// return NewLog(conf, decisionFilter, syncer)
		return nil, errors.New("backend not available")
	})
}

type Log struct {
	*local.Log
}

func NewLog(conf *Conf, decisionFilter audit.DecisionLogEntryFilter, syncer IngestSyncer) (*Log, error) {
	localLog, err := local.NewLog(&conf.Conf, decisionFilter)
	if err != nil {
		return nil, err
	}

	logger := zap.L().Named("auditlog").With(zap.String("backend", Backend))

	minFlushInterval := conf.Ingest.MinFlushInterval
	maxBatchSize := int(conf.Ingest.MaxBatchSize)
	flushTimeout := conf.Ingest.FlushTimeout
	numGo := int(conf.Ingest.NumGoRoutines)

	localLog.RegisterCallback(func() {
		schedule(localLog.Db, newMutexTimer(), syncer, minFlushInterval, flushTimeout, maxBatchSize, numGo, logger)
	})

	return &Log{
		localLog,
	}, nil
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

type mutexTimer struct {
	expireCh chan struct{}
	t        *time.Timer
	mu       sync.RWMutex
}

func newMutexTimer() *mutexTimer {
	return &mutexTimer{
		expireCh: make(chan struct{}, 1),
	}
}

func (mt *mutexTimer) set(waitDuration time.Duration) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	if mt.t == nil {
		mt.t = time.AfterFunc(waitDuration, func() {
			mt.expireCh <- struct{}{}
			// TODO(saml) could close/recreate a new channel each time if we want more than one listener
			// close(mt.wait)

			mt.mu.Lock()
			mt.t = nil
			mt.mu.Unlock()
		})
	}
}

func (mt *mutexTimer) wait() {
	{
		mt.mu.RLock()
		defer mt.mu.RUnlock()
		if mt.t == nil {
			return
		}
	}

	<-mt.expireCh
}

func schedule(db *badgerv4.DB, muTimer *mutexTimer, syncer IngestSyncer, minFlushInterval, flushTimeout time.Duration, maxBatchSize, numGo int, logger *zap.Logger) {
	muTimer.wait()

	if err := streamLogs(db, syncer, maxBatchSize, numGo, flushTimeout); err != nil {
		var ingestErr ErrIngestBackoff
		if errors.As(err, &ingestErr) {
			logger.Warn("svc-ingest issued backoff", zap.Error(err))
			muTimer.set(ingestErr.Backoff)
			go schedule(db, muTimer, syncer, minFlushInterval, flushTimeout, maxBatchSize, numGo, logger)
			return
		}
		logger.Warn("Failed sync", zap.Error(err))
	}

	// Set a min wait duration regardless of if events are pending.
	// This prevents a retry completion occurring immediately before the next sync
	// (and therefore burdening the backend).
	muTimer.set(minFlushInterval)
}

func streamLogs(db *badgerv4.DB, syncer IngestSyncer, maxBatchSize, numGo int, flushTimeout time.Duration) error {
	// BadgerDB transactions work with snapshot isolation so we only take a view of the DB.
	// Subsequent writes aren't blocked.
	stream := db.NewStream()
	stream.NumGo = numGo
	stream.Prefix = SyncStatusPrefix

	ctx, cancelFn := context.WithTimeout(context.Background(), flushTimeout)
	defer cancelFn()

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

			if err := syncThenDelete(ctx, db, syncer, keys[i:end]); err != nil {
				return err
			}
		}

		return nil
	}

	return stream.Orchestrate(ctx)
}

func syncThenDelete(ctx context.Context, db *badgerv4.DB, syncer IngestSyncer, batch [][]byte) error {
	if err := syncer.Sync(ctx, batch); err != nil {
		return err
	}

	wb := db.NewWriteBatch()
	defer wb.Cancel()

	for _, k := range batch {
		if err := wb.Delete(k); err != nil {
			if errors.Is(err, badgerv4.ErrDiscardedTxn) {
				wb = db.NewWriteBatch()
				_ = wb.Delete(k)
			} else {
				return err
			}
		}
	}

	return wb.Flush()
}

func (l *Log) Backend() string {
	return Backend
}
