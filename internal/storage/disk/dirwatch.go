// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package disk

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	defaultBufferSize uint = 8
	// defaultCooldownPeriod is the amount of time to wait before triggering a notification to update.
	// This is necessary because many file update events can fire even for a seemingly simple operation on a file.
	// We want the system to settle down before performing an expensive update operation.
	defaultCooldownPeriod = 2 * time.Second
)

type notifier interface {
	NotifySubscribers(events ...storage.Event)
}

func watchDir(ctx context.Context, dir string, idx index.Index, n notifier, cooldownPeriod time.Duration) (*dirWatch, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve directory %s: %w", dir, err)
	}

	watcher, err := fsnotify.NewBufferedWatcher(defaultBufferSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	if err := watcher.Add(resolved); err != nil {
		return nil, fmt.Errorf("failed to initiate monitoring on the directory %s: %w", resolved, err)
	}

	// We need to manually traverse the tree to add all directories because fsnotify package does not support recursive monitoring.
	// See https://github.com/fsnotify/fsnotify/issues/18 for more details.
	if err := filepath.WalkDir(resolved, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() || util.PathIsHidden(path) {
			return nil
		}

		if err := watcher.Add(path); err != nil {
			return fmt.Errorf("failed to initiate monitoring on the subdirectory %s: %w", path, err)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", resolved, err)
	}

	dw := &dirWatch{
		watcher:        watcher,
		idx:            idx,
		log:            zap.S().Named("dir.watch").With("dir", dir),
		eventBatch:     make(map[string]struct{}),
		notifier:       n,
		dir:            resolved,
		cooldownPeriod: cooldownPeriod,
	}

	go dw.listen(ctx) //nolint:gosec

	return dw, nil
}

type dirWatch struct {
	lastEventTime  time.Time
	watcher        *fsnotify.Watcher
	idx            index.Index
	log            *zap.SugaredLogger
	eventBatch     map[string]struct{}
	notifier       notifier
	dir            string
	cooldownPeriod time.Duration
	mu             sync.RWMutex
}

func (dw *dirWatch) listen(ctx context.Context) {
	ticker := time.NewTicker(dw.cooldownPeriod)
	defer func() {
		ticker.Stop()
		if err := dw.watcher.Close(); err != nil {
			dw.log.Warnw("Failed to close watcher", "error", err)
		}
	}()

	dw.log.Info("Watching directory for changes")

	for {
		select {
		case <-ctx.Done():
			dw.log.Info("Stopped watching directory for changes")
			return

		case event, ok := <-dw.watcher.Events:
			if !ok {
				dw.log.Info("Directory watch ended")
				return
			}

			dw.processEvent(event)

		case err, ok := <-dw.watcher.Errors:
			if !ok {
				dw.log.Info("Directory watch ended")
				return
			}

			dw.processError(err)

		case <-ticker.C:
			dw.mu.RLock()
			if !dw.shouldUpdate() {
				dw.mu.RUnlock()
				continue
			}
			dw.mu.RUnlock()

			dw.triggerUpdate()
			metrics.Inc(context.Background(), metrics.StorePollCount(), metrics.DriverKey(DriverName))
		}
	}
}

func (dw *dirWatch) processEvent(event fsnotify.Event) {
	if event.Op.Has(fsnotify.Create) && dw.watchNewSubDir(event.Name) {
		return
	}

	dw.log.Debugw("Processing an event", "operation", event.Op.String(), "name", event.Name)

	dw.batchEvent(event.Name)
}

// watchNewSubDir starts watching path and reports whether it was a newly created subdirectory.
// The watch is added on the creation event, because events in an unwatched directory are lost forever.
// Its existing contents are walked for the same reason:
// files and subdirectories created before the watch was added produce no events of their own.
func (dw *dirWatch) watchNewSubDir(path string) bool {
	if util.PathIsHidden(path) {
		return false
	}

	st, err := os.Stat(path)
	if err != nil || !st.IsDir() {
		return false
	}

	if err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			dw.batchEvent(path)
			return nil
		}

		if util.PathIsHidden(path) {
			return fs.SkipDir
		}

		return dw.watcher.Add(path)
	}); err != nil {
		dw.log.Errorw("Failed to initiate monitoring on the newly created subdirectory", "directory", path, "error", err)
	}

	return true
}

func (dw *dirWatch) batchEvent(fullPath string) {
	path, err := filepath.Rel(dw.dir, fullPath)
	if err != nil {
		dw.log.Warnw("Failed to determine relative path of file", "file", fullPath, "error", err)
		return
	}
	path = filepath.ToSlash(path)

	if util.FileType(path) == util.FileTypeNotIndexed {
		dw.log.Debugw("Encountered a non-indexable file type, skipping...", "file", path)
		return
	}

	dw.mu.Lock()
	dw.eventBatch[path] = struct{}{}
	dw.lastEventTime = time.Now()
	dw.mu.Unlock()
}

func (dw *dirWatch) processError(err error) {
	dw.log.Error("Processing an error", zap.Error(err))
}

func (dw *dirWatch) triggerUpdate() {
	dw.mu.Lock()
	if !dw.shouldUpdate() {
		dw.mu.Unlock()
		return
	}

	ts := time.Now().UnixMilli()
	eventBatch := dw.eventBatch
	dw.eventBatch = make(map[string]struct{})
	dw.mu.Unlock()

	errCount := 0
	// The deleted files need to be processed first because we could have a duplicate definition when a file is renamed otherwise.
	for path := range eventBatch {
		fullPath := filepath.Join(dw.dir, path)
		if _, err := os.Stat(fullPath); err == nil || !errors.Is(err, os.ErrNotExist) {
			continue
		}

		dw.log.Debugw("Detected file removal", "file", path)
		if sf, ok := util.RelativeSchemaPath(path); ok {
			delete(eventBatch, path)
			dw.notifier.NotifySubscribers(storage.NewSchemaEvent(storage.EventDeleteSchema, sf))
			continue
		}

		evt, err := dw.idx.Delete(index.Entry{File: path})
		if err != nil {
			dw.log.Warnw("Failed to remove file from index", "file", path, "error", err)
			errCount++
			continue
		}

		delete(eventBatch, path)
		dw.notifier.NotifySubscribers(evt)
	}

	for path := range eventBatch {
		fullPath := filepath.Join(dw.dir, path)
		dw.log.Debugw("Detected file update", "file", path)
		if sf, ok := util.RelativeSchemaPath(path); ok {
			dw.notifier.NotifySubscribers(storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, sf))
			continue
		}

		p, err := readPolicy(fullPath)
		if err != nil {
			dw.log.Warnw("Failed to read policy from file", "file", path, "error", err)
			errCount++
			continue
		}

		evt, err := dw.idx.AddOrUpdate(index.Entry{File: path, Policy: policy.Wrap(p)})
		if err != nil {
			dw.log.Warnw("Failed to add file to index", "file", path, "error", err)
			errCount++
			continue
		}

		dw.notifier.NotifySubscribers(evt)
	}

	if errCount > 0 {
		metrics.Add(context.Background(), metrics.StoreSyncErrorCount(), int64(errCount), metrics.DriverKey(DriverName))
	} else {
		metrics.Record(context.Background(), metrics.StoreLastSuccessfulRefresh(), ts, metrics.DriverKey(DriverName))
	}
}

func (dw *dirWatch) shouldUpdate() bool {
	return len(dw.eventBatch) > 0 && (time.Since(dw.lastEventTime) > dw.cooldownPeriod)
}

// TODO: use ReadPolicyFromFile instead.
func readPolicy(path string) (*policyv1.Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}

	defer f.Close()

	p, _, err := policy.ReadPolicy(f)
	return p, err
}
