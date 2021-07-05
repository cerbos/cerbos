// Copyright 2021 Zenauth Ltd.

package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	badgerv3 "github.com/dgraph-io/badger/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
)

const (
	badgerDiscardRatio      = 0.5
	goroutineResetThreshold = 1 << 16

	keyLen     = 20
	keyTSStart = 4
	keyTSEnd   = 10
)

var (
	accessLogPrefix   = []byte("aacc")
	decisionLogPrefix = []byte("adec")
)

func init() {
	audit.RegisterBackend("local", func(_ context.Context) (audit.Log, error) {
		return New()
	})
}

// New reads the configuration and returns a new instance of the Log.
func New() (*Log, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, fmt.Errorf("failed to read configuration: %w", err)
	}

	return NewLog(conf)
}

// Log implements the decisionlog interface with Badger as the backing store.
type Log struct {
	logger   *zap.Logger
	db       *badgerv3.DB
	buffer   chan *badgerv3.Entry
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopChan chan struct{}
	ttl      time.Duration
}

func NewLog(conf *Conf) (*Log, error) {
	logger := zap.L().Named("auditlog").With(zap.String("backend", "local"))
	opts := badgerv3.DefaultOptions(conf.StoragePath)
	opts = opts.WithCompactL0OnClose(true)
	opts = opts.WithMetricsEnabled(false)
	opts = opts.WithLogger(newDBLogger(logger))

	logger.Info("Initializing audit log", zap.String("path", conf.StoragePath))
	db, err := badgerv3.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	bufferSize := int(conf.Advanced.BufferSize)
	flushInterval := conf.Advanced.FlushInterval
	gcInterval := conf.Advanced.GCInterval
	maxBatchSize := int(conf.Advanced.MaxBatchSize)
	ttl := conf.RetentionPeriod

	l := &Log{
		logger:   logger,
		db:       db,
		buffer:   make(chan *badgerv3.Entry, bufferSize),
		stopChan: make(chan struct{}),
		ttl:      ttl,
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
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := newBatcher(l.db, maxBatchSize)
	logger := l.logger.With(zap.String("component", "batcher"))

	for i := 0; i < goroutineResetThreshold; i++ {
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

	for i := 0; i < goroutineResetThreshold; i++ {
		select {
		case <-l.stopChan:
			l.wg.Done()
			return
		case <-ticker.C:
			logger.Debug("Running value log GC")
			if err := l.db.RunValueLogGC(badgerDiscardRatio); err != nil {
				if !errors.Is(err, badgerv3.ErrNoRewrite) {
					logger.Error("Failed to run value log GC", zap.Error(err))
				}
			}
			logger.Debug("Finished running value log GC")
		}
	}

	// restart goroutine with a fresh stack
	go l.gc(gcInterval)
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

	key := genKey(accessLogPrefix, callID)

	return l.write(ctx, key, value)
}

func (l *Log) WriteDecisionLogEntry(ctx context.Context, record audit.DecisionLogEntryMaker) error {
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

	key := genKey(decisionLogPrefix, callID)

	return l.write(ctx, key, value)
}

func (l *Log) write(ctx context.Context, key, value []byte) error {
	select {
	case l.buffer <- badgerv3.NewEntry(key, value).WithTTL(l.ttl):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Log) LastNAccessLogEntries(ctx context.Context, n uint) audit.AccessLogIterator {
	c := newAccessLogEntryCollector()
	go l.listLastN(ctx, accessLogPrefix, n, c)

	return c
}

func (l *Log) LastNDecisionLogEntries(ctx context.Context, n uint) audit.DecisionLogIterator {
	c := newDecisionLogEntryCollector()
	go l.listLastN(ctx, decisionLogPrefix, n, c)

	return c
}

func (l *Log) listLastN(ctx context.Context, prefix []byte, n uint, c collector) {
	err := l.db.View(func(txn *badgerv3.Txn) error {
		opts := badgerv3.DefaultIteratorOptions
		opts.Reverse = true

		it := txn.NewIterator(opts)
		defer it.Close()

		key := maxScanKeyForPrefix(prefix)

		counter := uint(0)
		for it.Seek(key); it.ValidForPrefix(prefix); it.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}

			rec := it.Item()
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
	go l.listBetweenTimestamps(ctx, accessLogPrefix, fromTS, toTS, c)

	return c
}

func (l *Log) DecisionLogEntriesBetween(ctx context.Context, fromTS, toTS time.Time) audit.DecisionLogIterator {
	c := newDecisionLogEntryCollector()
	go l.listBetweenTimestamps(ctx, decisionLogPrefix, fromTS, toTS, c)

	return c
}

func (l *Log) listBetweenTimestamps(ctx context.Context, prefix []byte, fromTS, toTS time.Time, c collector) {
	start, err := minScanKeyForTime(prefix, fromTS)
	if err != nil {
		c.done(err)
		return
	}

	end, err := maxScanKeyForTime(prefix, toTS)
	if err != nil {
		c.done(err)
		return
	}

	err = l.db.View(func(txn *badgerv3.Txn) error {
		opts := badgerv3.DefaultIteratorOptions

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(start); it.Valid(); it.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}

			rec := it.Item()
			key := rec.Key()

			// stop when we have reached a key larger than the end key
			if bytes.Compare(key, end) >= 0 {
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

func (l *Log) Close() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		l.wg.Wait()
		l.db.Close()
	})
}

func genKey(prefix []byte, id audit.IDBytes) []byte {
	var key [keyLen]byte
	copy(key[:keyTSStart], prefix)
	copy(key[keyTSStart:], id[:])

	return key[:]
}

func genKeyForTime(prefix []byte, ts time.Time) ([]byte, error) {
	id, err := audit.NewIDForTime(ts)
	if err != nil {
		return nil, err
	}

	idBytes, err := id.Repr()
	if err != nil {
		return nil, err
	}

	return genKey(prefix, idBytes), nil
}

func minScanKeyForTime(prefix []byte, ts time.Time) ([]byte, error) {
	return scanKeyForTime(prefix, ts, 0x00) //nolint:gomnd
}

func maxScanKeyForTime(prefix []byte, ts time.Time) ([]byte, error) {
	return scanKeyForTime(prefix, ts, 0xFF) //nolint:gomnd
}

func scanKeyForTime(prefix []byte, ts time.Time, randFiller byte) ([]byte, error) {
	key, err := genKeyForTime(prefix, ts)
	if err != nil {
		return nil, err
	}

	for i := keyTSEnd; i < keyLen; i++ {
		key[i] = randFiller
	}

	return key, nil
}

func maxScanKeyForPrefix(prefix []byte) []byte {
	return scanKeyForPrefix(prefix, 0xFF) //nolint:gomnd
}

func scanKeyForPrefix(prefix []byte, filler byte) []byte {
	var key [keyLen]byte
	copy(key[:keyTSStart], prefix)

	for i := keyTSStart; i < keyLen; i++ {
		key[i] = filler
	}

	return key[:]
}

type batcher struct {
	db      *badgerv3.DB
	batch   []*badgerv3.Entry
	maxSize int
	ptr     int
}

func newBatcher(db *badgerv3.DB, maxSize int) *batcher {
	return &batcher{
		db:      db,
		batch:   make([]*badgerv3.Entry, maxSize),
		maxSize: maxSize,
	}
}

func (b *batcher) add(entry *badgerv3.Entry) error {
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

	for i := 0; i < b.ptr; i++ {
		entry := b.batch[i]
		if entry == nil {
			continue
		}

		if err := wb.SetEntry(entry); err != nil {
			if errors.Is(err, badgerv3.ErrDiscardedTxn) {
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

func newDBLogger(logger *zap.Logger) badgerv3.Logger {
	l := logger.Named("badger").WithOptions(zap.IncreaseLevel(zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl > zapcore.WarnLevel
	})))

	return zapLogger{SugaredLogger: l.Sugar()}
}

type zapLogger struct {
	*zap.SugaredLogger
}

func (zl zapLogger) Warningf(msg string, args ...interface{}) {
	zl.Warnf(msg, args...)
}
