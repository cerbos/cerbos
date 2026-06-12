// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/test/mocks"
)

const (
	cooldownPeriod = 30 * time.Millisecond
	timeOut        = 1000 * time.Millisecond
	// Long enough for an erroneously batched event to have been processed: that happens at the
	// earliest after ~2*cooldownPeriod (ticker interval + event cooldown), the rest is CI margin.
	noEventWait = cooldownPeriod * 5
)

func TestDirWatch(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	t.Run("add_file", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		subMgr := storage.NewSubscriptionManager(ctx)
		mockIdx := &mocks.Index{}
		dir := t.TempDir()

		_, err := watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod)
		require.NoError(t, err)

		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("AddOrUpdate", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: entry.Policy.ID}
		}, nil)

		checkEvents := storage.TestSubscription(subMgr)

		// Add some files
		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))

		touch(t, filepath.Join(dir, "test.txt"))
		writePolicy(t, filepath.Join(dir, "policy.yaml"), rp.Policy)

		select {
		case <-time.After(timeOut): // Wait time for events to be published.
			require.Fail(t, "timed out waiting for the entry")
		case have := <-haveEntries:
			require.Equal(t, "policy.yaml", have.File)
		}

		// Check expectations
		mockIdx.AssertExpectations(t)

		wantEvent := storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rp.ID}
		checkEvents(t, timeOut, wantEvent)
	})

	t.Run("delete_file", func(t *testing.T) {
		// Add some files
		dir := t.TempDir()
		policyFile := filepath.Join(dir, "policy.yaml")
		textFile := filepath.Join(dir, "test.txt")
		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))

		touch(t, textFile)
		writePolicy(t, policyFile, rp.Policy)

		// Start watch
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		subMgr := storage.NewSubscriptionManager(ctx)
		mockIdx := &mocks.Index{}

		_, err := watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod)
		require.NoError(t, err)

		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("Delete", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventDeleteOrDisablePolicy, PolicyID: entry.Policy.ID}
		}, nil)

		checkEvents := storage.TestSubscription(subMgr)

		// Delete the files
		require.NoError(t, os.Remove(policyFile))
		require.NoError(t, os.Remove(textFile))

		select {
		case <-time.After(timeOut): // Wait time for events to be published.
			require.Fail(t, "timed out waiting for the entry")
		case have := <-haveEntries:
			require.Equal(t, "policy.yaml", have.File)
		}

		// Check expectations
		mockIdx.AssertExpectations(t)

		wantEvent := storage.Event{Kind: storage.EventDeleteOrDisablePolicy}
		checkEvents(t, timeOut, wantEvent)
	})

	t.Run("add_schema_file", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		subMgr := storage.NewSubscriptionManager(ctx)
		mockIdx := &mocks.Index{}
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, schema.Directory), 0o744))

		_, err := watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod)
		require.NoError(t, err)

		checkEvents := storage.TestSubscription(subMgr)

		touch(t, filepath.Join(dir, schema.Directory, "test.json"))

		wantEvent := storage.Event{Kind: storage.EventAddOrUpdateSchema, SchemaFile: "test.json"}
		checkEvents(t, timeOut, wantEvent)
	})

	t.Run("delete_schema_file", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		subMgr := storage.NewSubscriptionManager(ctx)
		mockIdx := &mocks.Index{}
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, schema.Directory), 0o744))

		schemaFile := filepath.Join(dir, schema.Directory, "test.json")
		touch(t, schemaFile)

		_, err := watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod)
		require.NoError(t, err)

		checkEvents := storage.TestSubscription(subMgr)

		// delete the schema file
		require.NoError(t, os.Remove(schemaFile))

		wantEvent := storage.Event{Kind: storage.EventDeleteSchema, SchemaFile: "test.json"}
		checkEvents(t, timeOut, wantEvent)
	})

	// Reproducer for the regression introduced by the switch to fsnotify in PR #3061 (0b1e7983):
	// newly created subdirectories were never watched, so policies inside them were silently ignored.
	// The policy is written immediately after mkdir to also cover files that arrive before the watch attaches.
	t.Run("add_file_in_new_subdir", func(t *testing.T) {
		dw, haveEntries, checkEvents := startDirWatch(t)

		subDir := filepath.Join(dw.dir, "newdir")
		require.NoError(t, os.Mkdir(subDir, 0o755))

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		writePolicy(t, filepath.Join(subDir, "policy.yaml"), rp.Policy)

		select {
		case <-time.After(timeOut):
			require.Fail(t, "timed out waiting for entry from policy in dynamically created subdirectory")
		case have := <-haveEntries:
			require.Equal(t, "newdir/policy.yaml", have.File)
		}

		wantEvent := storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rp.ID}
		checkEvents(t, timeOut, wantEvent)
	})

	t.Run("add_file_in_nested_new_subdir", func(t *testing.T) {
		dw, haveEntries, checkEvents := startDirWatch(t)

		// MkdirAll creates the inner directory before the outer one is watched,
		// so only the outer directory's creation produces an event.
		// Everything below it must be found by scanning.
		inner := filepath.Join(dw.dir, "outer", "inner")
		require.NoError(t, os.MkdirAll(inner, 0o755))

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		writePolicy(t, filepath.Join(inner, "policy.yaml"), rp.Policy)

		select {
		case <-time.After(timeOut):
			require.Fail(t, "timed out waiting for entry from policy in nested dynamically created subdirectory")
		case have := <-haveEntries:
			require.Equal(t, "outer/inner/policy.yaml", have.File)
		}

		wantEvent := storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rp.ID}
		checkEvents(t, timeOut, wantEvent)
	})

	// Guards the fix against over-eagerly watching hidden directories.
	// The visible subdir acts as a positive control:
	// without it, a timeout could also mean the watcher isn't working at all.
	t.Run("new_hidden_subdir_ignored", func(t *testing.T) {
		dw, haveEntries, _ := startDirWatch(t)

		hidden := filepath.Join(dw.dir, ".hidden")
		require.NoError(t, os.Mkdir(hidden, 0o755))
		visible := filepath.Join(dw.dir, "visible")
		require.NoError(t, os.Mkdir(visible, 0o755))
		waitUntilWatched(t, dw, visible)
		require.NotContains(t, dw.watcher.WatchList(), hidden)

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		writePolicy(t, filepath.Join(hidden, "policy.yaml"), rp.Policy)
		writePolicy(t, filepath.Join(visible, "policy.yaml"), rp.Policy)

		select {
		case <-time.After(timeOut):
			require.Fail(t, "timed out waiting for entry from policy in visible subdirectory")
		case have := <-haveEntries:
			require.Equal(t, "visible/policy.yaml", have.File,
				"only the visible subdirectory's policy should be indexed")
		}

		select {
		case have := <-haveEntries:
			require.Failf(t, "unexpected entry from hidden subdirectory", "got %q", have.File)
		case <-time.After(noEventWait):
		}
	})
}

// The AddOrUpdate expectation is Maybe() so that tests expecting no calls can use the same helper.
func startDirWatch(t *testing.T) (dw *dirWatch, haveEntries chan index.Entry, checkEvents func(*testing.T, time.Duration, ...storage.Event)) {
	t.Helper()

	ctx, cancelFunc := context.WithCancel(t.Context())
	t.Cleanup(cancelFunc)

	subMgr := storage.NewSubscriptionManager(ctx)
	mockIdx := &mocks.Index{}

	dw, err := watchDir(ctx, t.TempDir(), mockIdx, subMgr, cooldownPeriod)
	require.NoError(t, err)

	haveEntries = make(chan index.Entry, 8)
	mockIdx.On("AddOrUpdate", mock.Anything).Return(func(entry index.Entry) storage.Event {
		haveEntries <- entry
		return storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: entry.Policy.ID}
	}, nil).Maybe()

	return dw, haveEntries, storage.TestSubscription(subMgr)
}

// waitUntilWatched blocks until dir joins the watch list,
// because events inside a not-yet-watched directory are lost forever and would make the calling test hang.
func waitUntilWatched(t *testing.T, dw *dirWatch, dir string) {
	t.Helper()

	require.Eventuallyf(t, func() bool {
		return slices.Contains(dw.watcher.WatchList(), dir)
	}, timeOut, time.Millisecond, "directory %s was never watched", dir)
}

func writePolicy(t *testing.T, fileName string, p *policyv1.Policy) {
	t.Helper()

	f, err := os.Create(fileName)
	require.NoError(t, err)

	defer f.Close()

	require.NoError(t, policy.WritePolicy(f, p))
}

func touch(t *testing.T, fileName string) {
	t.Helper()

	f, err := os.Create(fileName)
	require.NoError(t, err)

	require.NoError(t, f.Close())
}
