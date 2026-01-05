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

		require.NoError(t, watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod))

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

		require.NoError(t, watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod))

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

		require.NoError(t, watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod))

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

		require.NoError(t, watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod))

		checkEvents := storage.TestSubscription(subMgr)

		// delete the schema file
		require.NoError(t, os.Remove(schemaFile))

		wantEvent := storage.Event{Kind: storage.EventDeleteSchema, SchemaFile: "test.json"}
		checkEvents(t, timeOut, wantEvent)
	})
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
