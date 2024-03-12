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
	"go.uber.org/zap"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/cerboshub"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/test/mocks"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

const (
	numRecords = 2000
	batchSize  = uint(32)
)

type mockSyncer struct {
	*mocks.IngestSyncer
	synced map[string]struct{}
	t      *testing.T
}

func newMockSyncer(t *testing.T) *mockSyncer {
	return &mockSyncer{
		IngestSyncer: mocks.NewIngestSyncer(t),
		synced:       make(map[string]struct{}),
		t:            t,
	}
}

func (m *mockSyncer) Sync(ctx context.Context, batch *logsv1.IngestBatch) error {
	if err := m.IngestSyncer.Sync(ctx, batch); err != nil {
		return err
	}

	for _, e := range batch.Entries {
		var key []byte
		switch e.Kind {
		case logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG:
			key = keyFromCallID(m.t, e.GetAccessLogEntry().CallId, cerboshub.AccessSyncPrefix)
		case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
			key = keyFromCallID(m.t, e.GetDecisionLogEntry().CallId, cerboshub.DecisionSyncPrefix)
		}

		m.synced[string(key)] = struct{}{}
	}

	return nil
}

func keyFromCallID(t *testing.T, callID string, prefix []byte) []byte {
	t.Helper()

	callIDbytes, err := audit.ID(callID).Repr()
	require.NoError(t, err)

	return local.GenKey(prefix, callIDbytes)
}

func (m *mockSyncer) hasKeys(keys [][]byte) bool {
	m.t.Helper()

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
	db, err := cerboshub.NewLog(conf, decisionFilter, syncer, zap.L().Named("auditlog"))
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

	// We use two streams (access + decision log scans). Each independent stream ends up with a partial page, therefore
	// we treat each batch separately (hence the /2 -> *2 below).
	wantNumBatches := int(math.Ceil((numRecords/2)/float64(batchSize))) * 2

	t.Run("insertsAndDeletesKeys", func(t *testing.T) {
		t.Cleanup(purgeKeys)

		loadedKeys := loadData(t, db, startDate)

		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(nil).Times(wantNumBatches)

		db.ForceWrite()

		require.True(t, syncer.hasKeys(loadedKeys), "keys should have been synced")
		require.Empty(t, getLocalKeys(), "keys should have been deleted")
	})

	t.Run("partiallyDeletesBeforeError", func(t *testing.T) {
		t.Cleanup(purgeKeys)

		loadData(t, db, startDate)

		initialNBatches := int(math.Ceil(float64(wantNumBatches) * 0.2))

		// Server responds with unrecoverable error after first N pages
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(nil).Times(initialNBatches)
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(errors.New("some error")).Once()
		// the other concurrent stream exits with context cancellation
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(context.Canceled).Once()

		db.ForceWrite()

		require.Len(t, getLocalKeys(), (numRecords)-(initialNBatches*int(batchSize)), "some keys should have been deleted")
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

		db.ForceWrite()

		require.True(t, syncer.hasKeys(loadedKeys), "keys should have been synced")
		require.Empty(t, getLocalKeys(), "keys should have been deleted")
	})
}

func loadData(t *testing.T, db *cerboshub.Log, startDate time.Time) [][]byte {
	t.Helper()

	ctx := context.Background()
	syncKeys := make([][]byte, numRecords)
	for i := 0; i < (numRecords / 2); i++ {
		ts := startDate.Add(time.Duration(i) * time.Second)
		id, err := audit.NewIDForTime(ts)
		require.NoError(t, err)

		callID, err := audit.ID(string(id)).Repr()
		require.NoError(t, err)
		// We insert decision sync logs in the latter half as this is the same
		// order that Badger retrieves keys from the LSM
		syncKeys[i] = local.GenKey(cerboshub.AccessSyncPrefix, callID)
		syncKeys[i+(numRecords/2)] = local.GenKey(cerboshub.DecisionSyncPrefix, callID)

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
