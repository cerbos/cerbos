// Copyright 2021 Zenauth Ltd.

package disk

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/rjeczalik/notify"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/storage/common"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	// cooldownPeriod is the amount of time to wait before triggering a notification to update.
	// This is necessary because many file update events can fire even for a seemingly simple operation on a file.
	// We want the system to settle down before performing an expensive update operation.
	cooldownPeriod = 3 * time.Second
	notifyTimeout  = 2 * time.Second
	reloadTimeout  = 60 * time.Second
)

func newDirWatch(ctx context.Context, dir string, idx index.Index, notifier *common.Notifier) (*dirWatch, error) {
	dw := &dirWatch{
		log:       zap.S().Named("dir.watch").With("dir", dir),
		idx:       idx,
		watchChan: make(chan notify.EventInfo, 8), //nolint:gomnd
		Notifier:  notifier,
	}

	if err := notify.Watch(filepath.Join(dir, "..."), dw.watchChan, notify.All); err != nil {
		return nil, fmt.Errorf("failed to watch directory %s: %w", dir, err)
	}

	go dw.handleEvents(ctx)

	return dw, nil
}

type dirWatch struct {
	log       *zap.SugaredLogger
	watchChan chan notify.EventInfo
	idx       index.Index
	*common.Notifier
	mu            sync.RWMutex
	eventsSeen    bool
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
		dw.eventsSeen = true
		dw.lastEventTime = time.Now()
		dw.mu.Unlock()
	}
}

func (dw *dirWatch) triggerUpdate() {
	dw.mu.RLock()
	shouldUpdate := dw.eventsSeen && (time.Since(dw.lastEventTime) > cooldownPeriod)
	dw.mu.RUnlock()

	if shouldUpdate {
		dw.mu.Lock()
		proceed := dw.eventsSeen && (time.Since(dw.lastEventTime) > cooldownPeriod)
		if !proceed {
			dw.mu.Unlock()
			return
		}

		dw.eventsSeen = false
		dw.mu.Unlock()

		if err := dw.reloadIndex(); err != nil {
			dw.log.Errorw("Failed to reload index", "error", err)
			return
		}

		ctx, cancelFunc := context.WithTimeout(context.Background(), notifyTimeout)
		defer cancelFunc()

		if err := dw.NotifyFullUpdate(ctx); err != nil {
			dw.log.Warnw("Failed to send update notification: %w", err)
		}
	}
}

func (dw *dirWatch) reloadIndex() error {
	/*
		ctx, cancelFunc := context.WithTimeout(context.Background(), reloadTimeout)
		defer cancelFunc()

		dw.log.Debug("Reloading index")
		if err := dw.index.Reload(ctx); err != nil {
			return err
		}

		dw.log.Info("Index reloaded")
	*/
	return nil
}
