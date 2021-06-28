// Copyright 2021 Zenauth Ltd.

package badgerdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	badgerv3 "github.com/dgraph-io/badger/v3"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/decisionlog/common"
	decisionlogv1 "github.com/cerbos/cerbos/internal/genpb/decisionlog/v1"
)

const (
	badgerDiscardRatio      = 0.5
	goroutineResetThreshold = 1 << 16

	keyLen     = 20
	keyTSStart = 4
	keyTSEnd   = 10
)

var prefix = []byte("audt")

// Log implements the decisionlog interface with Badger as the backing store.
type Log struct {
	logger   *zap.Logger
	db       *badgerv3.DB
	ulidGen  *common.ULIDGen
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
		ulidGen:  common.NewULIDGen(uint64(runtime.NumCPU()), time.Now().UnixNano()),
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

func (l *Log) Add(ctx context.Context, record *decisionlogv1.Decision) error {
	value, err := record.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	var ts time.Time
	if record.RequestTime != nil {
		ts = record.RequestTime.AsTime()
	} else {
		ts = time.Now()
	}

	key, err := l.genKey(ts)
	if err != nil {
		return fmt.Errorf("failed to generate ULID: %w", err)
	}

	select {
	case l.buffer <- badgerv3.NewEntry(key, value).WithTTL(l.ttl):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

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

func (l *Log) genKey(ts time.Time) ([]byte, error) {
	ulid, err := l.ulidGen.NewForTime(ts)
	if err != nil {
		return nil, err
	}

	var key [keyLen]byte
	copy(key[:keyTSStart], prefix)
	copy(key[keyTSStart:], ulid[:])

	return key[:], nil
}

func (l *Log) minScanKey(ts time.Time) ([]byte, error) {
	return l.scanKey(ts, 0x00) //nolint:gomnd
}

func (l *Log) maxScanKey(ts time.Time) ([]byte, error) {
	return l.scanKey(ts, 0xFF) //nolint:gomnd
}

func (l *Log) scanKey(ts time.Time, randFiller byte) ([]byte, error) {
	key, err := l.genKey(ts)
	if err != nil {
		return nil, err
	}

	for i := keyTSEnd; i < keyLen; i++ {
		key[i] = randFiller
	}

	return key, nil
}

func (l *Log) Close() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		l.wg.Wait()
		l.db.Close()
	})
}

type zapLogger struct {
	*zap.SugaredLogger
}

func (zl zapLogger) Warningf(msg string, args ...interface{}) {
	zl.Warnf(msg, args...)
}
