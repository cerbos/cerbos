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
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	badgerv4 "github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/ristretto/z"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/zap"
)

const (
	Backend = "cerboshub"
)

var (
	SyncStatusPrefix   = []byte("bs")   // "b" for contiguity with audit log keys in LSM, "s" because "sync"
	AccessSyncPrefix   = []byte("bsac") // these need to be len(4) to correctly reuse `local.GenKey`
	DecisionSyncPrefix = []byte("bsde")
)

func init() {
	audit.RegisterBackend(Backend, func(_ context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read cerboshub audit log configuration: %w", err)
		}

		logger := zap.L().Named("auditlog").With(zap.String("backend", Backend))

		syncer, err := NewIngestSyncer(conf, logger)
		if err != nil {
			return nil, err
		}

		return NewLog(conf, decisionFilter, syncer, logger)
	})
}

type Log struct {
	*local.Log
}

func NewLog(conf *Conf, decisionFilter audit.DecisionLogEntryFilter, syncer IngestSyncer, logger *zap.Logger) (*Log, error) {
	localLog, err := local.NewLog(&conf.Conf, decisionFilter)
	if err != nil {
		return nil, err
	}

	logger.Info("Extending audit log")

	minFlushInterval := conf.Ingest.MinFlushInterval
	maxBatchSize := int(conf.Ingest.MaxBatchSize)
	flushTimeout := conf.Ingest.FlushTimeout
	numGo := int(conf.Ingest.NumGoRoutines)

	localLog.RegisterCallback(func(waitCh chan<- struct{}) {
		schedule(localLog.Db, newMutexTimer(), syncer, minFlushInterval, flushTimeout, maxBatchSize, numGo, logger, waitCh)
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
	// TODO(saml) retrieve key generated in embedded call above to avoid recalc?
	value := local.GenKey(local.AccessLogPrefix, callID)

	return l.Write(ctx, key, value)
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
	// TODO(saml) retrieve key generated in embedded call above to avoid recalc?
	value := local.GenKey(local.DecisionLogPrefix, callID)

	return l.Write(ctx, key, value)
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

func schedule(db *badgerv4.DB, muTimer *mutexTimer, syncer IngestSyncer, minFlushInterval, flushTimeout time.Duration, maxBatchSize, numGo int, logger *zap.Logger, waitCh chan<- struct{}) {
	muTimer.wait()

	if err := streamLogs(db, syncer, maxBatchSize, numGo, flushTimeout); err != nil {
		var ingestErr ErrIngestBackoff
		if errors.As(err, &ingestErr) {
			logger.Warn("svc-ingest issued backoff", zap.Error(err))
			muTimer.set(ingestErr.Backoff)
			go schedule(db, muTimer, syncer, minFlushInterval, flushTimeout, maxBatchSize, numGo, logger, waitCh)
			return
		}
		logger.Warn("Failed sync", zap.Error(err))
	}

	// Set a min wait duration regardless of if events are pending.
	// This prevents a retry completion occurring immediately before the next sync
	// (and therefore burdening the backend).
	muTimer.set(minFlushInterval)

	waitCh <- struct{}{}
}

func streamLogs(db *badgerv4.DB, syncer IngestSyncer, maxBatchSize, numGo int, flushTimeout time.Duration) error {
	// We use two streams: one for access logs, and one for decision logs, as this allows us to
	// avoid the penalty of per-key string inspection when inferring the type down the line.
	ctx := context.Background()

	p := pool.New().WithContext(ctx).WithCancelOnError().WithFirstError()
	p.Go(func(ctx context.Context) error {
		return streamPrefix(ctx, db, syncer, maxBatchSize, numGo, flushTimeout, logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, AccessSyncPrefix)
	})
	p.Go(func(ctx context.Context) error {
		return streamPrefix(ctx, db, syncer, maxBatchSize, numGo, flushTimeout, logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG, DecisionSyncPrefix)
	})

	return p.Wait()
}

func streamPrefix(ctx context.Context, db *badgerv4.DB, syncer IngestSyncer, maxBatchSize, numGo int, flushTimeout time.Duration, kind logsv1.IngestBatch_EntryKind, prefix []byte) error {
	// BadgerDB transactions work with snapshot isolation so we only take a view of the DB.
	// Subsequent writes aren't blocked.
	stream := db.NewStream()
	stream.NumGo = numGo
	stream.Prefix = prefix

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

			if err := syncThenDelete(ctx, db, syncer, kind, keys[i:end], flushTimeout); err != nil {
				return err
			}
		}

		return nil
	}

	return stream.Orchestrate(ctx)
}

func syncThenDelete(ctx context.Context, db *badgerv4.DB, syncer IngestSyncer, kind logsv1.IngestBatch_EntryKind, syncKeys [][]byte, flushTimeout time.Duration) error {
	entries, err := getIngestBatchEntries(db, syncKeys, kind)
	if err != nil {
		return err
	}

	batchID, err := audit.NewID()
	if err != nil {
		return err
	}

	{
		ctx, cancelFn := context.WithTimeout(ctx, flushTimeout)
		defer cancelFn()

		if err := syncer.Sync(ctx, &logsv1.IngestBatch{
			Id:      string(batchID),
			Entries: entries,
		}); err != nil {
			return err
		}
	}

	wb := db.NewWriteBatch()
	defer wb.Cancel()

	for _, k := range syncKeys {
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

func getIngestBatchEntries(db *badgerv4.DB, syncKeys [][]byte, kind logsv1.IngestBatch_EntryKind) ([]*logsv1.IngestBatch_Entry, error) {
	entries := make([]*logsv1.IngestBatch_Entry, len(syncKeys))
	if err := db.Update(func(txn *badgerv4.Txn) error {
		for i, k := range syncKeys {
			syncItem, err := txn.Get(k)
			if err != nil {
				return err
			}

			var logKey []byte
			if err := syncItem.Value(func(v []byte) error {
				logKey = v
				return nil
			}); err != nil {
				return err
			}

			logItem, err := txn.Get(logKey)
			if err != nil {
				return err
			}

			var entry *logsv1.IngestBatch_Entry
			if err := logItem.Value(func(v []byte) error {
				switch kind {
				case logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG:
					accessLog := &auditv1.AccessLogEntry{}
					if err := accessLog.UnmarshalVT(v); err != nil {
						return err
					}

					entry = &logsv1.IngestBatch_Entry{
						Kind: logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG,
						Entry: &logsv1.IngestBatch_Entry_AccessLogEntry{
							AccessLogEntry: accessLog,
						},
						Timestamp: accessLog.Timestamp,
					}
				case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
					decisionLog := &auditv1.DecisionLogEntry{}
					if err := decisionLog.UnmarshalVT(v); err != nil {
						return err
					}

					entry = &logsv1.IngestBatch_Entry{
						Kind: logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
						Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
							DecisionLogEntry: decisionLog,
						},
						Timestamp: decisionLog.Timestamp,
					}
				case logsv1.IngestBatch_ENTRY_KIND_UNSPECIFIED:
					return errors.New("unspecified IngestBatch_EntryKind")
				}

				return nil
			}); err != nil {
				return err
			}

			entries[i] = entry
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return entries, nil
}

func (l *Log) Backend() string {
	return Backend
}
