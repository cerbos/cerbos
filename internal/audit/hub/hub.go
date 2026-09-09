// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

const (
	Backend = "hub"

	maxAllowedBatchSize = 1024
)

type syncPrefix []byte

var (
	SyncStatusPrefix   = syncPrefix("bs")   // "b" for contiguity with audit log keys in LSM, "s" because "sync"
	AccessSyncPrefix   = syncPrefix("bsac") // these need to be len(4) to correctly reuse `local.GenKey`
	DecisionSyncPrefix = syncPrefix("bsde")
)

func init() {
	audit.RegisterBackend(Backend, func(ctx context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read hub audit log configuration: %w", err)
		}

		logger := zap.L().Named("auditlog").With(zap.String("backend", Backend))

		syncer, err := NewIngestSyncer(logger)
		if err != nil {
			return nil, err
		}

		var pipeLog audit.Log
		if conf.PipeOutput.Enabled {
			cons, err := audit.GetBackend(conf.PipeOutput.Backend)
			if err != nil {
				return nil, err
			}

			pipeLog, err = cons(ctx, confW, decisionFilter)
			if err != nil {
				return nil, fmt.Errorf("failed to construct pipe output backend: %w", err)
			}
		}

		return NewLog(conf, decisionFilter, syncer, logger, pipeLog)
	})
}

type options struct {
	maxBatchSize int
}

type Opt func(*options)

func WithMaxBatchSize(maxBatchSize int) Opt {
	return func(o *options) {
		o.maxBatchSize = maxBatchSize
	}
}

type Log struct {
	syncer          IngestSyncer
	pipeLog         audit.Log
	cancel          context.CancelFunc
	filter          *AuditLogFilter
	oversizedFilter *AuditLogFilter
	pool            *pool.ContextPool
	logger          *zap.Logger
	*local.Log
	minFlushInterval  time.Duration
	flushTimeout      time.Duration
	maxBatchSize      int
	maxBatchSizeBytes int
	numGo             int
}

func NewLog(conf *Conf, decisionFilter audit.DecisionLogEntryFilter, syncer IngestSyncer, logger *zap.Logger, pipeLog audit.Log, opts ...Opt) (*Log, error) {
	o := &options{
		maxBatchSize: maxAllowedBatchSize,
	}

	for _, opt := range opts {
		opt(o)
	}

	localLog, err := local.NewLog(&conf.Conf, decisionFilter)
	if err != nil {
		return nil, err
	}

	logger.Info("Extending audit log")

	minFlushInterval := conf.Ingest.MinFlushInterval
	maxBatchSizeBytes := int(conf.Ingest.MaxBatchSizeBytes) - BatchSizeToleranceBytes
	flushTimeout := conf.Ingest.FlushTimeout
	numGo := int(conf.Ingest.NumGoRoutines)

	filter, err := NewAuditLogFilter(conf.Mask)
	if err != nil {
		return nil, err
	}

	oversizedFilter, err := NewOversizedLogFilter()
	if err != nil {
		return nil, err
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	log := &Log{
		Log:               localLog,
		syncer:            syncer,
		logger:            logger,
		filter:            filter,
		oversizedFilter:   oversizedFilter,
		minFlushInterval:  minFlushInterval,
		flushTimeout:      flushTimeout,
		maxBatchSize:      o.maxBatchSize,
		maxBatchSizeBytes: maxBatchSizeBytes,
		numGo:             numGo,
		cancel:            cancelFn,
		pool:              pool.New().WithContext(ctx),
		pipeLog:           pipeLog,
	}

	log.pool.Go(log.syncLoop)
	return log, nil
}

func (l *Log) WriteAccessLogEntry(ctx context.Context, record audit.AccessLogEntryMaker) error { //nolint:dupl
	rec, err := record()
	if err != nil {
		return err
	}

	entry := &logsv1.IngestBatch_Entry{
		Entry: &logsv1.IngestBatch_Entry_AccessLogEntry{
			AccessLogEntry: rec,
		},
	}

	if err := l.filter.Filter(entry); err != nil {
		return fmt.Errorf("failed to filter batch: %w", err)
	}

	rec = entry.GetAccessLogEntry()

	if l.pipeLog != nil {
		if err := l.pipeLog.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
			return rec, nil
		}); err != nil {
			l.logger.Warn("Failed to write access log entry to pipe", zap.Error(err))
		}
	}

	s := entry.SizeVT()
	if s > l.maxBatchSizeBytes {
		l.logger.Error("Entry exceeds maximum batch size, masking",
			zap.Int("entrySize", s),
			zap.Int("maxAllowedBatchSizeBytes", l.maxBatchSizeBytes))
		metrics.Inc(ctx, metrics.AuditOversizedEntryCount(), metrics.KindKey(audit.KindAccess))

		if err := l.oversizedFilter.Filter(entry); err != nil {
			return fmt.Errorf("failed to filter oversized batch: %w", err)
		}

		rec = entry.GetAccessLogEntry()
		rec.Oversized = true

		// the entry has been shrunk, update the size
		s = entry.SizeVT()
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

	key := local.GenKeyWithByteSize(AccessSyncPrefix, callID, s)
	value := local.GenKey(local.AccessLogPrefix, callID)

	return l.Write(ctx, key, value)
}

func (l *Log) WriteDecisionLogEntry(ctx context.Context, record audit.DecisionLogEntryMaker) error { //nolint:dupl
	rec, err := record()
	if err != nil {
		return err
	}

	entry := &logsv1.IngestBatch_Entry{
		Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
			DecisionLogEntry: rec,
		},
	}

	if err := l.filter.Filter(entry); err != nil {
		return fmt.Errorf("failed to filter batch: %w", err)
	}

	rec = entry.GetDecisionLogEntry()

	if l.pipeLog != nil {
		if err := l.pipeLog.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
			return rec, nil
		}); err != nil {
			l.logger.Warn("Failed to write decision log entry to pipe", zap.Error(err))
		}
	}

	s := entry.SizeVT()
	if s > l.maxBatchSizeBytes {
		l.logger.Error("Entry exceeds maximum batch size, masking",
			zap.Int("entrySize", s),
			zap.Int("maxAllowedBatchSizeBytes", l.maxBatchSizeBytes))
		metrics.Inc(ctx, metrics.AuditOversizedEntryCount(), metrics.KindKey(audit.KindDecision))

		if err := l.oversizedFilter.Filter(entry); err != nil {
			return fmt.Errorf("failed to filter oversized batch: %w", err)
		}

		rec = entry.GetDecisionLogEntry()
		rec.Oversized = true

		// the entry has been shrunk, update the size
		s = entry.SizeVT()
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

	key := local.GenKeyWithByteSize(DecisionSyncPrefix, callID, s)
	value := local.GenKey(local.DecisionLogPrefix, callID)

	return l.Write(ctx, key, value)
}

func (l *Log) syncLoop(ctx context.Context) error {
	ticker := time.NewTicker(l.minFlushInterval)
	for {
		select {
		case <-ticker.C:
			ticker.Stop()
			delay := l.schedule()
			ticker.Reset(delay)
		case <-ctx.Done():
			return nil
		}
	}
}

func (l *Log) schedule() time.Duration {
	l.logger.Log(zapcore.Level(-3), "Scheduling stream")
	if err := l.streamLogs(); err != nil {
		if ingestErr, ok := errors.AsType[ErrIngestBackoff](err); ok {
			l.logger.Warn("svc-ingest issued backoff", zap.Error(err))
			if ingestErr.Backoff < l.minFlushInterval {
				return l.minFlushInterval
			}
			return ingestErr.Backoff
		}
		l.logger.Error("Audit log sync failed", zap.Error(err))
	}

	return l.minFlushInterval
}

func (l *Log) streamLogs() error {
	// We use two streams: one for access logs, and one for decision logs, as this allows us to
	// avoid the penalty of per-key string inspection when inferring the type down the line.
	ctx := context.Background()

	p := pool.New().WithContext(ctx).WithCancelOnError()
	p.Go(func(ctx context.Context) error {
		l.logger.Log(zapcore.Level(-2), "Streaming access logs")
		if err := l.streamPrefix(ctx, logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, AccessSyncPrefix); err != nil {
			l.logger.Warn("Failed to stream access logs", zap.Error(err))
			return fmt.Errorf("failed to stream access logs: %w", err)
		}
		l.logger.Log(zapcore.Level(-2), "Finished streaming access logs")
		return nil
	})

	p.Go(func(ctx context.Context) error {
		l.logger.Log(zapcore.Level(-2), "Streaming decision logs")
		if err := l.streamPrefix(ctx, logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG, DecisionSyncPrefix); err != nil {
			l.logger.Warn("Failed to stream decision logs", zap.Error(err))
			return fmt.Errorf("failed to stream decision logs: %w", err)
		}
		l.logger.Log(zapcore.Level(-2), "Finished streaming decision logs")
		return nil
	})

	if err := p.Wait(); err != nil {
		l.logger.Warn("Failed to stream logs", zap.Error(err))
		return fmt.Errorf("failed to stream logs: %w", err)
	}
	return nil
}

var keysPool = &sync.Pool{}

// maxEntrySeekLinearSteps is a maximum number of times iterator.Next() can be
// called before falling back to a Seek. Markers and entries share the call-ID
// ordering, so in the common case each marker's entry is at most a few
// positions ahead.
const maxEntrySeekLinearSteps = 8

// streamPrefix walks the sync markers under prefix and the entries they point
// at with two lockstep iterators inside one snapshot.
func (l *Log) streamPrefix(ctx context.Context, kind logsv1.IngestBatch_EntryKind, prefix syncPrefix) error {
	logger := l.logger.With(zap.Stringer("kind", kind))

	var entryPrefix []byte
	switch kind { //nolint:exhaustive
	case logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG:
		entryPrefix = local.AccessLogPrefix
	case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
		entryPrefix = local.DecisionLogPrefix
	default:
		return errors.New("unspecified IngestBatch_EntryKind")
	}

	fallbacks := 0
	err := l.Db.View(func(txn *badgerv4.Txn) error {
		markerOpts := badgerv4.DefaultIteratorOptions
		markerOpts.Prefix = prefix
		markerOpts.PrefetchValues = false
		markerIt := txn.NewIterator(markerOpts)
		defer markerIt.Close()

		entryOpts := badgerv4.DefaultIteratorOptions
		entryOpts.Prefix = entryPrefix
		entryOpts.PrefetchValues = false
		entryIt := txn.NewIterator(entryOpts)
		defer entryIt.Close()
		entryIt.Seek(entryPrefix)

		var keys [][]byte
		if keysIface := keysPool.Get(); keysIface == nil {
			keys = make([][]byte, l.maxBatchSize)
		} else {
			keys = *keysIface.(*[][]byte) //nolint:forcetypeassert
			if len(keys) < l.maxBatchSize {
				keys = make([][]byte, l.maxBatchSize)
			}
		}
		defer keysPool.Put(&keys)

		// entries[j] is nil when the entry for keys[j] has expired; the
		// orphaned marker is still deleted along with the rest of the batch
		entries := make([]*logsv1.IngestBatch_Entry, l.maxBatchSize)

		lk := newLegacyKeys(l, kind, logger)
		defer lk.cancel()

		var logKey []byte
		var i int
		var batchSizeBytes int

		flushBatch := func(ks [][]byte, es []*logsv1.IngestBatch_Entry) error {
			if len(ks) == 0 {
				return nil
			}
			logger.Log(zapcore.Level(-3), "Syncing and deleting batch",
				zap.Int("batchSize", len(ks)))
			if err := l.syncThenDelete(ctx, kind, ks, es); err != nil {
				return fmt.Errorf("failed to sync and delete logs: %w", err)
			}
			return nil
		}

		for markerIt.Seek(prefix); markerIt.ValidForPrefix(prefix); markerIt.Next() {
			item := markerIt.Item()
			k := item.Key()

			if err := item.Value(func(v []byte) error {
				logKey = append(logKey[:0], v...)
				return nil
			}); err != nil {
				return err
			}

			var entry *logsv1.IngestBatch_Entry
			steps := 0
		advance:
			for entryIt.ValidForPrefix(entryPrefix) {
				switch cmp := bytes.Compare(entryIt.Item().Key(), logKey); {
				case cmp == 0:
					if err := entryIt.Item().Value(func(v []byte) error {
						var err error
						entry, err = mkIngestBatchEntry(kind, v)
						return err
					}); err != nil {
						return err
					}
					entryIt.Next()
					break advance
				case cmp > 0:
					break advance
				default:
					steps++
					if steps > maxEntrySeekLinearSteps {
						entryIt.Seek(logKey)
						steps = 0
					} else {
						entryIt.Next()
					}
				}
			}

			if entry == nil {
				fallbacks++
				var err error
				if entry, err = getEntry(txn, kind, logKey); err != nil {
					return err
				}
			}

			legacy := lk.isLegacy(k)
			var size int
			if legacy {
				size = entry.SizeVT()
			} else {
				size = int(binary.BigEndian.Uint32(k[local.KeyByteSizeStart:]))
			}

			// An oversized legacy entry cannot be synced as-is.
			if legacy && size > l.maxBatchSizeBytes {
				if err := lk.rewriteOversized(ctx, entry, item.KeyCopy(nil)); err != nil {
					return err
				}
				continue
			}

			// Cut the batch if this entry would overflow it.
			if i > 0 && (i == l.maxBatchSize || batchSizeBytes+size > l.maxBatchSizeBytes) {
				if err := flushBatch(keys[:i], entries[:i]); err != nil {
					return err
				}
				i = 0
				batchSizeBytes = 0
			}

			keys[i] = append(keys[i][:0], k...)
			entries[i] = entry
			batchSizeBytes += size
			i++
		}

		lk.flush()

		return flushBatch(keys[:i], entries[:i])
	})
	if fallbacks > 0 {
		logger.Log(zapcore.Level(-2), "Entry lookups fell back to point reads", zap.Int("count", fallbacks))
	}
	return err
}

// syncThenDelete sends the non-nil entries as one IngestBatch and, on success,
// deletes all the batch's marker keys. nil entries mark expired records whose
// markers are cleaned up along with the rest.
func (l *Log) syncThenDelete(ctx context.Context, kind logsv1.IngestBatch_EntryKind, syncKeys [][]byte, batchEntries []*logsv1.IngestBatch_Entry) error {
	logger := l.logger.With(zap.Stringer("kind", kind))

	entries := make([]*logsv1.IngestBatch_Entry, 0, len(batchEntries))
	for _, entry := range batchEntries {
		if entry != nil {
			entries = append(entries, entry)
		}
	}

	if len(entries) == 0 {
		logger.Log(zapcore.Level(-3), "Ingest batch is empty")
		return nil
	}

	logger.Log(zapcore.Level(-3), "Generating audit ID")
	batchID, err := audit.NewID()
	if err != nil {
		return fmt.Errorf("failed to generate audit ID: %w", err)
	}

	{
		ctx, cancelFn := context.WithTimeout(ctx, l.flushTimeout)
		defer cancelFn()

		ingestBatch := &logsv1.IngestBatch{
			Id:      string(batchID),
			Entries: entries,
		}

		logger.Log(zapcore.Level(-3), "Syncing batch of "+strconv.Itoa(len(ingestBatch.Entries)))
		if err := l.syncer.Sync(ctx, ingestBatch); err != nil {
			return fmt.Errorf("failed to sync batch: %w", err)
		}
	}

	wb := l.Db.NewWriteBatch()
	defer wb.Cancel()

	logger.Log(zapcore.Level(-3), "Deleting synced keys")
	for _, k := range syncKeys {
		if err := wb.Delete(k); err != nil {
			if errors.Is(err, badgerv4.ErrDiscardedTxn) {
				wb.Cancel()
				wb = l.Db.NewWriteBatch()
				_ = wb.Delete(k)
			} else {
				return fmt.Errorf("failed to delete key: %w", err)
			}
		}
	}

	logger.Log(zapcore.Level(-3), "Flushing write batch")
	return wb.Flush()
}

func getEntry(txn *badgerv4.Txn, kind logsv1.IngestBatch_EntryKind, logKey []byte) (entry *logsv1.IngestBatch_Entry, err error) {
	item, err := txn.Get(logKey)
	if err != nil {
		if errors.Is(err, badgerv4.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}

	if err = item.Value(func(v []byte) error {
		entry, err = mkIngestBatchEntry(kind, v)
		return err
	}); err != nil {
		return nil, err
	}

	return entry, nil
}

// mkIngestBatchEntry wraps the serialized entry bytes into an IngestBatch_Entry.
func mkIngestBatchEntry(kind logsv1.IngestBatch_EntryKind, raw []byte) (*logsv1.IngestBatch_Entry, error) {
	switch kind { //nolint:exhaustive
	case logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG:
		accessLog := &auditv1.AccessLogEntry{}
		if err := accessLog.UnmarshalVT(raw); err != nil {
			return nil, err
		}

		return &logsv1.IngestBatch_Entry{
			Kind: logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG,
			Entry: &logsv1.IngestBatch_Entry_AccessLogEntry{
				AccessLogEntry: accessLog,
			},
			Timestamp: accessLog.Timestamp,
		}, nil
	case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
		decisionLog := &auditv1.DecisionLogEntry{}
		if err := decisionLog.UnmarshalVT(raw); err != nil {
			return nil, err
		}

		return &logsv1.IngestBatch_Entry{
			Kind: logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
			Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
				DecisionLogEntry: decisionLog,
			},
			Timestamp: decisionLog.Timestamp,
		}, nil
	default:
		return nil, errors.New("unspecified IngestBatch_EntryKind")
	}
}

func (l *Log) Backend() string {
	return Backend
}

func (l *Log) Close() (outErr error) {
	l.cancel()
	outErr = errors.Join(outErr, l.pool.Wait())
	outErr = errors.Join(outErr, l.Db.Sync())
	outErr = errors.Join(outErr, l.Log.Close())
	return outErr
}
