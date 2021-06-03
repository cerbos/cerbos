// Copyright 2021 Zenauth Ltd.

package disk

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rjeczalik/notify"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	// cooldownPeriod is the amount of time to wait before triggering a notification to update.
	// This is necessary because many file update events can fire even for a seemingly simple operation on a file.
	// We want the system to settle down before performing an expensive update operation.
	cooldownPeriod = 2 * time.Second
)

func watchDir(ctx context.Context, dir string, idx index.Index, sub *storage.SubscriptionManager) error {
	dw := &dirWatch{
		log:                 zap.S().Named("dir.watch").With("dir", dir),
		idx:                 idx,
		SubscriptionManager: sub,
		eventBatch:          make(map[string]struct{}),
		watchChan:           make(chan notify.EventInfo, 8), //nolint:gomnd
	}

	if err := notify.Watch(filepath.Join(dir, "..."), dw.watchChan, notify.All); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", dir, err)
	}

	go dw.handleEvents(ctx)

	return nil
}

type dirWatch struct {
	log       *zap.SugaredLogger
	watchChan chan notify.EventInfo
	idx       index.Index
	*storage.SubscriptionManager
	mu            sync.RWMutex
	eventBatch    map[string]struct{}
	lastEventTime time.Time
}

func (dw *dirWatch) handleEvents(ctx context.Context) {
	ticker := time.NewTicker(cooldownPeriod)

	defer func() {
		ticker.Stop()
		notify.Stop(dw.watchChan)
	}()

	dw.log.Info("Watching directory for changes")

	for {
		select {
		case <-ctx.Done():
			dw.log.Info("Stopped watching directory for changes")
			return
		case evtInfo := <-dw.watchChan:
			dw.processEvent(evtInfo)
		case <-ticker.C:
			dw.triggerUpdate()
		}
	}
}

func (dw *dirWatch) processEvent(evtInfo notify.EventInfo) {
	if util.IsSupportedFileType(evtInfo.Path()) {
		dw.mu.Lock()
		dw.eventBatch[evtInfo.Path()] = struct{}{}
		dw.lastEventTime = time.Now()
		dw.mu.Unlock()
	}
}

func (dw *dirWatch) triggerUpdate() {
	dw.mu.RLock()
	shouldUpdate := len(dw.eventBatch) > 0 && (time.Since(dw.lastEventTime) > cooldownPeriod)
	dw.mu.RUnlock()

	//nolint:nestif
	if shouldUpdate {
		dw.mu.Lock()
		proceed := len(dw.eventBatch) > 0 && (time.Since(dw.lastEventTime) > cooldownPeriod)
		if !proceed {
			dw.mu.Unlock()
			return
		}

		batch := dw.eventBatch
		dw.eventBatch = make(map[string]struct{})
		dw.mu.Unlock()

		for f := range batch {
			if _, err := os.Stat(f); errors.Is(err, os.ErrNotExist) {
				dw.log.Debugw("Detected file removal", "file", f)
				evt, err := dw.idx.Delete(index.Entry{File: f})
				if err != nil {
					dw.log.Warnw("Failed to remove file from index", "file", f, "error", err)
					continue
				}

				dw.NotifySubscribers(evt)
				continue
			}

			dw.log.Debugw("Detected file update", "file", f)
			evt, err := dw.idx.AddOrUpdate(index.Entry{File: f})
			if err != nil {
				dw.log.Warnw("Failed to add file to index", "file", f, "error", err)
				continue
			}

			dw.NotifySubscribers(evt)
		}
	}
}
