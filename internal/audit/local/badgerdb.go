// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/badgerkey"
	"github.com/cerbos/cerbos/internal/config"
)

const (
	badgerDiscardRatio      = 0.5
	goroutineResetThreshold = 1 << 16

	Backend = "local"
)

func init() {
	audit.RegisterBackend(Backend, func(_ context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read local audit log configuration: %w", err)
		}

		return NewLog(conf, decisionFilter)
	})
}

// Log implements the decisionlog interface with Badger as the backing store.
type Log struct {
	logger                   *zap.Logger
	Db                       *badgerv4.DB
	buffer                   chan *badgerv4.Entry
	stopChan                 chan struct{}
	decisionFilter           audit.DecisionLogEntryFilter
	KeyPrefix                []byte
	wg                       sync.WaitGroup
	ttl                      time.Duration
	stopOnce                 sync.Once
	bufferSize, maxBatchSize int
	flushInterval            time.Duration
}

func NewLog(conf *Conf, decisionFilter audit.DecisionLogEntryFilter) (*Log, error) {
	logger := zap.L().Named("auditlog").With(zap.String("backend", Backend))
	opts := badgerv4.DefaultOptions(conf.StoragePath)
	opts = opts.WithCompactL0OnClose(true)
	opts = opts.WithMetricsEnabled(false)
	opts = opts.WithLogger(newDBLogger(logger))
	opts = opts.WithMemTableSize(int64(conf.Advanced.MemtableSize))
	opts = opts.WithValueLogFileSize(512 << 20) //nolint:mnd
	opts = opts.WithBlockSize(64 << 10)         //nolint:mnd

	logger.Info("Initializing audit log", zap.String("path", conf.StoragePath))
	db, err := badgerv4.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	bufferSize := int(conf.Advanced.BufferSize)
	flushInterval := conf.Advanced.FlushInterval
	gcInterval := conf.Advanced.GCInterval
	maxBatchSize := int(conf.Advanced.MaxBatchSize)
	ttl := conf.RetentionPeriod

	l := &Log{
		logger:         logger,
		Db:             db,
		buffer:         make(chan *badgerv4.Entry, bufferSize),
		stopChan:       make(chan struct{}),
		ttl:            ttl,
		decisionFilter: decisionFilter,
		bufferSize:     bufferSize,
		maxBatchSize:   maxBatchSize,
		flushInterval:  flushInterval,
	}

	l.wg.Add(1)
	go l.batchWriter(maxBatchSize, flushInterval)

	if gcInterval > 0 {
		l.wg.Add(1)
		go l.gc(gcInterval)
	}

	return l, nil
}

func (l *Log) batchWriter(maxBatchSize int, flushInterval time.Duration) {
	batch := newBatcher(l.Db, maxBatchSize)
	logger := l.logger.With(zap.String("component", "batcher"))

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for range goroutineResetThreshold {
		select {
		case <-l.stopChan:
			batch.flush()
			l.wg.Done()
			return
		case entry, ok := <-l.buffer:
			if !ok {
				batch.flush()
				l.wg.Done()
				return
			}

			if err := batch.add(entry); err != nil {
				logger.Warn("Failed to add entry to batch", zap.Error(err))
				continue
			}
		case <-ticker.C:
			batch.flush()
		}
	}

	batch.flush()
	// restart the goroutine with a fresh stack
	go l.batchWriter(maxBatchSize, flushInterval)
}

func (l *Log) gc(gcInterval time.Duration) {
	logger := l.logger.With(zap.String("component", "gc"))
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()

	for range goroutineResetThreshold {
		select {
		case <-l.stopChan:
			l.wg.Done()
			return
		case <-ticker.C:
			logger.Debug("Running value log GC")
			if err := l.Db.RunValueLogGC(badgerDiscardRatio); err != nil {
				if !errors.Is(err, badgerv4.ErrNoRewrite) {
					logger.Error("Failed to run value log GC", zap.Error(err))
				}
			}
			logger.Debug("Finished running value log GC")
		}
	}

	// restart goroutine with a fresh stack
	go l.gc(gcInterval)
}

func (l *Log) Backend() string {
	return Backend
}

func (l *Log) Enabled() bool {
	return true
}

// ForceWrite forces a write operation and blocks until completion. It is used only by tests.
// It deadlocks if gc goroutine is running, that is when gcInterval isn't zero.
func (l *Log) ForceWrite() {
	close(l.buffer)
	l.wg.Wait()

	// Restart the batching goroutine
	l.buffer = make(chan *badgerv4.Entry, l.bufferSize)
	l.wg.Add(1)
	go l.batchWriter(l.maxBatchSize, l.flushInterval)
}

func (l *Log) WriteAccessLogEntry(ctx context.Context, record audit.AccessLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	value, err := rec.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	key := l.Key(badgerkey.KindAccessLogEntry, callID, badgerkey.WithoutByteSize)

	return l.Write(ctx, key, value)
}

func (l *Log) WriteDecisionLogEntry(ctx context.Context, record audit.DecisionLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	if l.decisionFilter != nil {
		rec = l.decisionFilter(rec)
		if rec == nil {
			return nil
		}
	}

	value, err := rec.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	key := l.Key(badgerkey.KindDecisionLogEntry, callID, badgerkey.WithoutByteSize)

	return l.Write(ctx, key, value)
}

func (l *Log) Write(ctx context.Context, key badgerkey.Key, value []byte) error {
	select {
	case l.buffer <- badgerv4.NewEntry(key, value).WithTTL(l.ttl):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Log) LastNAccessLogEntries(ctx context.Context, n uint) audit.AccessLogIterator {
	c := newAccessLogEntryCollector()
	go l.listLastN(ctx, badgerkey.KindAccessLogEntry, n, c)

	return c
}

func (l *Log) LastNDecisionLogEntries(ctx context.Context, n uint) audit.DecisionLogIterator {
	c := newDecisionLogEntryCollector()
	go l.listLastN(ctx, badgerkey.KindDecisionLogEntry, n, c)

	return c
}

func (l *Log) listLastN(ctx context.Context, kind badgerkey.Kind, n uint, c collector) {
	minKey, maxKey := badgerkey.KindRange(l.KeyPrefix, kind)

	err := l.Db.View(func(txn *badgerv4.Txn) error {
		opts := badgerv4.DefaultIteratorOptions
		opts.Reverse = true

		it := txn.NewIterator(opts)
		defer it.Close()

		counter := uint(0)
		for it.Seek(maxKey); it.Valid(); it.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}

			rec := it.Item()

			if bytes.Compare(rec.Key(), minKey) < 0 {
				return nil
			}

			if err := rec.Value(c.add); err != nil {
				return err
			}

			counter++
			if counter >= n {
				return nil
			}
		}

		return nil
	})

	c.done(err)
}

func (l *Log) AccessLogEntriesBetween(ctx context.Context, fromTS, toTS time.Time) audit.AccessLogIterator {
	c := newAccessLogEntryCollector()
	go l.listBetweenTimestamps(ctx, badgerkey.KindAccessLogEntry, fromTS, toTS, c)

	return c
}

func (l *Log) DecisionLogEntriesBetween(ctx context.Context, fromTS, toTS time.Time) audit.DecisionLogIterator {
	c := newDecisionLogEntryCollector()
	go l.listBetweenTimestamps(ctx, badgerkey.KindDecisionLogEntry, fromTS, toTS, c)

	return c
}

func (l *Log) listBetweenTimestamps(ctx context.Context, kind badgerkey.Kind, fromTS, toTS time.Time, c collector) {
	minKey, maxKey := badgerkey.TimeRange(l.KeyPrefix, kind, fromTS, toTS)

	err := l.Db.View(func(txn *badgerv4.Txn) error {
		opts := badgerv4.DefaultIteratorOptions

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(minKey); it.Valid(); it.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}

			rec := it.Item()

			if bytes.Compare(rec.Key(), maxKey) > 0 {
				return nil
			}

			if err := rec.Value(c.add); err != nil {
				return err
			}
		}

		return nil
	})

	c.done(err)
}

func (l *Log) AccessLogEntryByID(ctx context.Context, id audit.ID) audit.AccessLogIterator {
	c := newAccessLogEntryCollector()
	l.getByID(ctx, badgerkey.KindAccessLogEntry, id, c)
	return c
}

func (l *Log) DecisionLogEntryByID(ctx context.Context, id audit.ID) audit.DecisionLogIterator {
	c := newDecisionLogEntryCollector()
	l.getByID(ctx, badgerkey.KindDecisionLogEntry, id, c)
	return c
}

func (l *Log) getByID(ctx context.Context, kind badgerkey.Kind, id audit.ID, c collector) {
	if err := ctx.Err(); err != nil {
		c.done(err)
		return
	}

	idBytes, err := id.Repr()
	if err != nil {
		c.done(err)
		return
	}

	key := l.Key(kind, idBytes, badgerkey.WithoutByteSize)
	err = l.Db.View(func(txn *badgerv4.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if errors.Is(err, badgerv4.ErrKeyNotFound) {
				return audit.ErrIteratorClosed
			}

			return err
		}

		return item.Value(c.add)
	})

	c.done(err)
}

func (l *Log) Close() error {
	var err error
	l.stopOnce.Do(func() {
		close(l.stopChan)
		l.wg.Wait()
		err = l.Db.Close()
	})
	return err
}

func (l *Log) Key(kind badgerkey.Kind, id audit.IDBytes, byteSize int) badgerkey.Key {
	return badgerkey.New(l.KeyPrefix, kind, id, byteSize)
}

type batcher struct {
	db      *badgerv4.DB
	batch   []*badgerv4.Entry
	maxSize int
	ptr     int
}

func newBatcher(db *badgerv4.DB, maxSize int) *batcher {
	return &batcher{
		db:      db,
		batch:   make([]*badgerv4.Entry, maxSize),
		maxSize: maxSize,
	}
}

func (b *batcher) add(entry *badgerv4.Entry) error {
	b.batch[b.ptr] = entry
	b.ptr++

	if b.ptr >= b.maxSize {
		return b.flush()
	}

	return nil
}

func (b *batcher) flush() error {
	wb := b.db.NewWriteBatch()
	defer func() {
		b.ptr = 0
		wb.Cancel()
	}()

	for i := range b.ptr {
		entry := b.batch[i]
		if entry == nil {
			continue
		}

		if err := wb.SetEntry(entry); err != nil {
			if errors.Is(err, badgerv4.ErrDiscardedTxn) {
				wb = b.db.NewWriteBatch()
				_ = wb.SetEntry(entry)
			} else {
				return err
			}
		}
		b.batch[i] = nil
	}

	return wb.Flush()
}

func newDBLogger(logger *zap.Logger) badgerv4.Logger {
	l := logger.Named("badger").WithOptions(zap.IncreaseLevel(zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl > zapcore.WarnLevel
	})))

	return zapLogger{SugaredLogger: l.Sugar()}
}

type zapLogger struct {
	*zap.SugaredLogger
}

func (zl zapLogger) Warningf(msg string, args ...any) {
	zl.Warnf(msg, args...)
}
