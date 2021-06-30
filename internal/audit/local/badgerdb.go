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
	logger := zap.L().Named("decisionlog[badger]")
	opts := badgerv3.DefaultOptions(conf.StoragePath)
	opts = opts.WithCompactL0OnClose(true)
	opts = opts.WithMetricsEnabled(false)
	opts = opts.WithLoggingLevel(badgerv3.WARNING)
	opts = opts.WithLogger(zapLogger{SugaredLogger: logger.With(zap.String("component", "engine")).Sugar()})

	db, err := badgerv3.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	maxPendingTransactions := defaultMaxPendingTransactions
	flushInterval := defaultFlushInterval
	bufferSize := defaultBufferSize
	gcInterval := defaultGCInterval
	ttl := conf.RetentionPeriod

	if conf.Advanced != nil {
		maxPendingTransactions = int(conf.Advanced.MaxPendingTransactions)
		flushInterval = conf.Advanced.FlushInterval
		bufferSize = int(conf.Advanced.BufferSize)
		gcInterval = conf.Advanced.GCInterval
	}

	l := &Log{
		logger:   logger,
		db:       db,
		buffer:   make(chan *badgerv3.Entry, bufferSize),
		stopChan: make(chan struct{}),
		ttl:      ttl,
	}

	l.wg.Add(1)
	go l.batchWriter(maxPendingTransactions, flushInterval)

	if gcInterval > 0 {
		l.wg.Add(1)
		go l.gc(gcInterval)
	}

	return l, nil
}

func (l *Log) batchWriter(maxPendingTransactions int, flushInterval time.Duration) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := l.db.NewWriteBatch()
	defer batch.Cancel()

	batch.SetMaxPendingTxns(maxPendingTransactions)

	logger := l.logger.With(zap.String("component", "batcher"))

	flush := func() {
		logger.Debug("Flushing batch")
		if err := batch.Flush(); err != nil {
			logger.Error("Failed to flush batch", zap.Error(err))
		}
	}

	for i := 0; i < goroutineResetThreshold; i++ {
		select {
		case <-l.stopChan:
			flush()
			l.wg.Done()
			return
		case entry, ok := <-l.buffer:
			if !ok {
				flush()
				l.wg.Done()
				return
			}

			if err := batch.SetEntry(entry); err != nil {
				logger.Warn("Failed to add entry to batch", zap.Error(err))
				continue
			}
		case <-ticker.C:
			flush()
		}
	}

	flush()
	// restart the goroutine with a fresh stack
	go l.batchWriter(maxPendingTransactions, flushInterval)
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

	key := genKey(accessLogPrefix, rec.CallId)

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

	key := genKey(decisionLogPrefix, rec.CallId)

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

/*
func (l *Log) ListLastN(ctx context.Context, n uint) (<-chan common.LogEntry, error) {
	results := make(chan common.LogEntry, 1)
	go func() {
		defer close(results)

		err := l.db.View(func(txn *badgerv3.Txn) error {
			opts := badgerv3.DefaultIteratorOptions
			opts.Reverse = true

			it := txn.NewIterator(opts)
			defer it.Close()

			counter := uint(0)
			for it.Rewind(); it.Valid(); it.Next() {
				if err := ctx.Err(); err != nil {
					return err
				}

				rec := it.Item()
				err := rec.Value(func(v []byte) error {
					d := &decisionlogv1.Decision{}
					if err := d.UnmarshalVT(v); err != nil {
						results <- common.LogEntry{Err: err}
						return err
					}

					results <- common.LogEntry{Decision: d}
					return nil
				})
				if err != nil {
					return err
				}

				counter++
				if counter >= n {
					return nil
				}
			}

			return nil
		})

		if err != nil && !errors.Is(err, context.Canceled) {
			l.logger.Warn("Failed to list last N records", zap.Error(err), zap.Uint("n", n))
		}
	}()

	return results, nil
}

func (l *Log) ListBetweenTimestamps(ctx context.Context, fromTS, toTS time.Time) (<-chan common.LogEntry, error) {
	start, err := l.minScanKey(fromTS)
	if err != nil {
		return nil, err
	}

	end, err := l.maxScanKey(toTS)
	if err != nil {
		return nil, err
	}

	results := make(chan common.LogEntry, 1)

	go func() {
		defer close(results)

		err := l.db.View(func(txn *badgerv3.Txn) error {
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

				err := rec.Value(func(v []byte) error {
					d := &decisionlogv1.Decision{}
					if err := d.UnmarshalVT(v); err != nil {
						results <- common.LogEntry{Err: err}
						return err
					}

					results <- common.LogEntry{Decision: d}
					return nil
				})
				if err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil && !errors.Is(err, context.Canceled) {
			l.logger.Warn("Failed to list records between timestamps", zap.Error(err))
		}
	}()

	return results, nil
}
*/

func (l *Log) Close() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		l.wg.Wait()
		l.db.Close()
	})
}

func genKey(prefix, id []byte) []byte {
	var key [keyLen]byte
	copy(key[:keyTSStart], prefix)
	copy(key[keyTSStart:], id)

	return key[:]
}

func genKeyForTime(prefix []byte, ts time.Time) ([]byte, error) {
	id, err := audit.NewIDForTime(ts)
	if err != nil {
		return nil, err
	}

	return genKey(prefix, id[:]), nil
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

type zapLogger struct {
	*zap.SugaredLogger
}

func (zl zapLogger) Warningf(msg string, args ...interface{}) {
	zl.Warnf(msg, args...)
}
