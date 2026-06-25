// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"os"
	"path/filepath"
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
		dir := t.TempDir()
		mockIdx, checkEvents := startDirWatch(t, dir)

		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("AddOrUpdate", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: entry.Policy.ID}
		}, nil)

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

	t.Run("add_file_to_new_subdirectory", func(t *testing.T) {
		dir := t.TempDir()
		mockIdx, checkEvents := startDirWatch(t, dir)

		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("AddOrUpdate", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: entry.Policy.ID}
		}, nil)

		subDir := filepath.Join(dir, "subdirectory")
		require.NoError(t, os.Mkdir(subDir, 0o700))

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		writePolicy(t, filepath.Join(subDir, "policy.yaml"), rp.Policy)

		select {
		case <-time.After(timeOut):
			require.Fail(t, "timed out waiting for entry")
		case have := <-haveEntries:
			require.Equal(t, "subdirectory/policy.yaml", have.File)
		}

		wantEvent := storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rp.ID}
		checkEvents(t, timeOut, wantEvent)
	})

	t.Run("add_file_to_nested_subdirectories", func(t *testing.T) {
		dir := t.TempDir()
		mockIdx, checkEvents := startDirWatch(t, dir)

		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("AddOrUpdate", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: entry.Policy.ID}
		}, nil)

		inner := filepath.Join(dir, "outer", "inner")
		require.NoError(t, os.MkdirAll(inner, 0o700))

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		writePolicy(t, filepath.Join(inner, "policy.yaml"), rp.Policy)

		select {
		case <-time.After(timeOut):
			require.Fail(t, "timed out waiting for entry")
		case have := <-haveEntries:
			require.Equal(t, "outer/inner/policy.yaml", have.File)
		}

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
		mockIdx, checkEvents := startDirWatch(t, dir)

		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("Delete", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventDeleteOrDisablePolicy, PolicyID: entry.Policy.ID}
		}, nil)

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
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, schema.Directory), 0o744))
		_, checkEvents := startDirWatch(t, dir)

		touch(t, filepath.Join(dir, schema.Directory, "test.json"))

		wantEvent := storage.Event{Kind: storage.EventAddOrUpdateSchema, SchemaFile: "test.json"}
		checkEvents(t, timeOut, wantEvent)
	})

	t.Run("delete_schema_file", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, schema.Directory), 0o744))

		schemaFile := filepath.Join(dir, schema.Directory, "test.json")
		touch(t, schemaFile)

		_, checkEvents := startDirWatch(t, dir)

		// delete the schema file
		require.NoError(t, os.Remove(schemaFile))

		wantEvent := storage.Event{Kind: storage.EventDeleteSchema, SchemaFile: "test.json"}
		checkEvents(t, timeOut, wantEvent)
	})

	t.Run("new_hidden_subdir_ignored", func(t *testing.T) {
		dir := t.TempDir()
		mockIdx, _ := startDirWatch(t, dir)
		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("AddOrUpdate", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: entry.Policy.ID}
		}, nil)

		hidden := filepath.Join(dir, ".hidden")
		require.NoError(t, os.Mkdir(hidden, 0o755))
		visible := filepath.Join(dir, "visible")
		require.NoError(t, os.Mkdir(visible, 0o755))

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		writePolicy(t, filepath.Join(hidden, "policy.yaml"), rp.Policy)
		writePolicy(t, filepath.Join(visible, "policy.yaml"), rp.Policy)

		select {
		case <-time.After(timeOut):
			require.Fail(t, "timed out waiting for entry")
		case have := <-haveEntries:
			require.Equal(t, "visible/policy.yaml", have.File)
		}

		select {
		case have := <-haveEntries:
			require.Failf(t, "unexpected entry from hidden subdirectory", "got %q", have.File)
		case <-time.After(noEventWait):
		}
	})
}

type checkEventsFn func(*testing.T, time.Duration, ...storage.Event)

func startDirWatch(t *testing.T, dir string) (*mocks.Index, checkEventsFn) {
	t.Helper()

	ctx, cancelFunc := context.WithCancel(t.Context())
	t.Cleanup(cancelFunc)

	subMgr := storage.NewSubscriptionManager(ctx)
	mockIdx := &mocks.Index{}

	require.NoError(t, watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod))
	return mockIdx, storage.TestSubscription(subMgr)
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
