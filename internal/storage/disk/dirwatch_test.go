// Copyright 2021 Zenauth Ltd.
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
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/test/mocks"
)

const (
	cooldownPeriod = 30 * time.Millisecond
	sleepTime      = 100 * time.Millisecond
)

func TestDirWatch(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	t.Run("add_file", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
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

		// Wait for events to be published. This is kind of brittle but better than nothing.
		time.Sleep(sleepTime)

		// Check expectations
		mockIdx.AssertExpectations(t)

		require.Len(t, haveEntries, 1)
		have := <-haveEntries
		require.Equal(t, "policy.yaml", have.File)

		wantEvent := storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: rp.ID}
		checkEvents(t, wantEvent)
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
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		subMgr := storage.NewSubscriptionManager(ctx)
		mockIdx := &mocks.Index{}

		require.NoError(t, watchDir(ctx, dir, mockIdx, subMgr, cooldownPeriod))

		haveEntries := make(chan index.Entry, 8)
		mockIdx.On("Delete", mock.Anything).Return(func(entry index.Entry) storage.Event {
			haveEntries <- entry
			return storage.Event{Kind: storage.EventDeletePolicy, PolicyID: entry.Policy.ID}
		}, nil)

		checkEvents := storage.TestSubscription(subMgr)

		// Delete the files
		require.NoError(t, os.Remove(policyFile))
		require.NoError(t, os.Remove(textFile))

		// Wait for events to be published. This is kind of brittle but better than nothing.
		time.Sleep(sleepTime)

		// Check expectations
		mockIdx.AssertExpectations(t)

		require.Len(t, haveEntries, 1)
		have := <-haveEntries
		require.Equal(t, "policy.yaml", have.File)

		wantEvent := storage.Event{Kind: storage.EventDeletePolicy}
		checkEvents(t, wantEvent)
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
