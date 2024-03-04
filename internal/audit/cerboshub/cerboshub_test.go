// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race
// +build !race

package cerboshub_test

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	badgerv4 "github.com/dgraph-io/badger/v4"
	gocmp "github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/cerboshub"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/test/mocks"
)

const (
	numRecords = 1000
	batchSize  = uint(32)
)

type mockSyncer struct {
	*mocks.IngestSyncer
	synced map[string]struct{}
}

func newMockSyncer(t *testing.T) *mockSyncer {
	t.Helper()

	return &mockSyncer{
		IngestSyncer: mocks.NewIngestSyncer(t),
		synced:       make(map[string]struct{}),
	}
}

func (m *mockSyncer) Sync(ctx context.Context, batch [][]byte) error {
	for _, key := range batch {
		m.synced[string(key)] = struct{}{}
	}

	return m.IngestSyncer.Sync(ctx, batch)
}

func (m *mockSyncer) hasKeys(keys [][]byte) bool {
	for _, k := range keys {
		if _, ok := m.synced[string(k)]; !ok {
			return false
		}
	}

	return true
}

func TestCerbosHubLog(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conf := &cerboshub.Conf{
		local.Conf{
			StoragePath:     t.TempDir(),
			RetentionPeriod: 24 * time.Hour,
			Advanced: local.AdvancedConf{
				BufferSize:    1,
				MaxBatchSize:  32,
				FlushInterval: 10 * time.Second,
			},
		},
		cerboshub.IngestConf{
			MaxBatchSize:     batchSize,
			MinFlushInterval: 2 * time.Second,
			FlushTimeout:     1 * time.Second,
			NumGoRoutines:    8,
		},
	}

	require.NoError(t, conf.Validate())

	startDate, err := time.Parse(time.RFC3339, "2021-01-01T10:00:00Z")
	require.NoError(t, err)

	decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
	syncer := newMockSyncer(t)
	db, err := cerboshub.NewLog(conf, decisionFilter, syncer)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, cerboshub.Backend, db.Backend())
	require.True(t, db.Enabled())

	purgeKeys := func() {
		err := db.Db.DropAll()
		require.NoError(t, err, "failed to purge keys")
	}

	getLocalKeys := func() [][]byte {
		t.Helper()

		keys := [][]byte{}
		err := db.Db.View(func(txn *badgerv4.Txn) error {
			opts := badgerv4.DefaultIteratorOptions
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Seek(cerboshub.SyncStatusPrefix); it.ValidForPrefix(cerboshub.SyncStatusPrefix); it.Next() {
				item := it.Item()
				key := make([]byte, len(item.Key()))
				copy(key, item.Key())
				keys = append(keys, key)
			}
			return nil
		})
		require.NoError(t, err)

		return keys
	}

	wantNumBatches := int(math.Ceil(numRecords * 2 / float64(batchSize)))

	t.Run("insertsKeys", func(t *testing.T) {
		t.Cleanup(purgeKeys)

		wantKeys := loadData(t, db, startDate)

		db.ForceWrite(true)

		keys := getLocalKeys()
		require.Len(t, keys, len(wantKeys), "incorrect number of keys: %d", len(keys))
		require.Empty(t, gocmp.Diff(wantKeys, keys, protocmp.Transform()))
	})

	t.Run("deletesKeys", func(t *testing.T) {
		t.Cleanup(purgeKeys)

		loadedKeys := loadData(t, db, startDate)

		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("[][]uint8")).Return(nil).Times(wantNumBatches)

		db.ForceWrite(false)

		require.True(t, syncer.hasKeys(loadedKeys), "keys should have been synced")
		require.Empty(t, getLocalKeys(), "keys should have been deleted")
	})

	t.Run("partiallyDeletesBeforeError", func(t *testing.T) {
		t.Cleanup(purgeKeys)

		loadedKeys := loadData(t, db, startDate)

		initialNBatches := int(math.Ceil(float64(wantNumBatches) * 0.2))

		// Server responds with unrecoverable error after first N pages
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("[][]uint8")).Return(nil).Times(initialNBatches)
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("[][]uint8")).Return(errors.New("some error")).Once()

		db.ForceWrite(false)

		require.True(t, syncer.hasKeys(loadedKeys[0:initialNBatches*int(batchSize)]), "some keys should have been synced")
		require.Len(t, getLocalKeys(), (numRecords*2)-(initialNBatches*int(batchSize)), "some keys should have been deleted")
	})

	t.Run("deletesSyncKeysAfterBackoff", func(t *testing.T) {
		t.Skip("TODO: We need to block until retry goroutine is complete")
		t.Cleanup(purgeKeys)

		loadedKeys := loadData(t, db, startDate)

		initialNBatches := int(math.Ceil(float64(wantNumBatches) * 0.2))

		// Server responds with backoff after first N pages
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("[][]uint8")).Return(nil).Times(initialNBatches)
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("[][]uint8")).Return(cerboshub.ErrIngestBackoff{
			Backoff: 0,
		}).Once()
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("[][]uint8")).Return(nil).Times(wantNumBatches - initialNBatches)

		db.ForceWrite(false)
		// The second callbackFn call happens in a separate goroutine. A short sleep gives it time to complete
		// TODO(saml) remove this sleep with some proper wait mechanism
		time.Sleep(100 * time.Millisecond)

		require.True(t, syncer.hasKeys(loadedKeys), "keys should have been synced")
		require.Empty(t, getLocalKeys(), "keys should have been deleted")
	})
}

func loadData(t *testing.T, db *cerboshub.Log, startDate time.Time) [][]byte {
	t.Helper()

	ctx := context.Background()
	syncKeys := make([][]byte, numRecords*2)
	for i := 0; i < numRecords; i++ {
		ts := startDate.Add(time.Duration(i) * time.Second)
		id, err := audit.NewIDForTime(ts)
		require.NoError(t, err)

		callID, err := audit.ID(string(id)).Repr()
		require.NoError(t, err)
		// We insert decision sync logs in the latter half as this is the same
		// order that Badger retrieves keys from the LSM
		syncKeys[i] = local.GenKey(cerboshub.AccessSyncPrefix, callID)
		syncKeys[i+numRecords] = local.GenKey(cerboshub.DecisionSyncPrefix, callID)

		err = db.WriteAccessLogEntry(ctx, mkAccessLogEntry(t, id, i, ts))
		require.NoError(t, err)

		err = db.WriteDecisionLogEntry(ctx, mkDecisionLogEntry(t, id, i, ts))
		require.NoError(t, err)
	}

	return syncKeys
}

func mkAccessLogEntry(t *testing.T, id audit.ID, i int, ts time.Time) audit.AccessLogEntryMaker {
	t.Helper()

	return func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId:    string(id),
			Timestamp: timestamppb.New(ts),
			Peer: &auditv1.Peer{
				Address: "1.1.1.1",
			},
			Metadata: map[string]*auditv1.MetaValues{"Num": {Values: []string{strconv.Itoa(i)}}},
			Method:   "/cerbos.svc.v1.CerbosService/Check",
		}, nil
	}
}

func mkDecisionLogEntry(t *testing.T, id audit.ID, i int, ts time.Time) audit.DecisionLogEntryMaker {
	t.Helper()

	return func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId:    string(id),
			Timestamp: timestamppb.New(ts),
			Inputs: []*enginev1.CheckInput{
				{
					RequestId: strconv.Itoa(i),
					Resource: &enginev1.Resource{
						Kind: "test:kind",
						Id:   "test",
					},
					Principal: &enginev1.Principal{
						Id:    "test",
						Roles: []string{"a", "b"},
					},
					Actions: []string{"a1", "a2"},
				},
			},
			Outputs: []*enginev1.CheckOutput{
				{
					RequestId:  strconv.Itoa(i),
					ResourceId: "test",
					Actions: map[string]*enginev1.CheckOutput_ActionEffect{
						"a1": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
						"a2": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
					},
				},
			},
		}, nil
	}
}
