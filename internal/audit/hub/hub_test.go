// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !race
// +build !race

package hub_test

import (
	"context"
	"errors"
	"math"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/hub"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/config"

	// Allows to set CERBOS_TEST_LOG_LEVEL environment variable.
	_ "github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/test/mocks"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

const (
	numRecords    = 2000
	batchSize     = uint(32)
	flushInterval = 5 * time.Millisecond
)

type mockSyncer struct {
	*mocks.IngestSyncer
	entries []*logsv1.IngestBatch_Entry
	synced  map[string]struct{}
	t       *testing.T
	mu      sync.RWMutex
}

func newMockSyncer(t *testing.T) *mockSyncer {
	t.Helper()

	return &mockSyncer{
		IngestSyncer: mocks.NewIngestSyncer(t),
		entries:      []*logsv1.IngestBatch_Entry{},
		synced:       make(map[string]struct{}),
		t:            t,
	}
}

func (m *mockSyncer) Sync(ctx context.Context, batch *logsv1.IngestBatch) error {
	if err := m.IngestSyncer.Sync(ctx, batch); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries = append(m.entries, batch.Entries...)

	for _, e := range batch.Entries {
		var key []byte
		switch e.Kind {
		case logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG:
			key = keyFromCallID(m.t, e.GetAccessLogEntry().CallId, hub.AccessSyncPrefix)
		case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
			key = keyFromCallID(m.t, e.GetDecisionLogEntry().CallId, hub.DecisionSyncPrefix)
		case logsv1.IngestBatch_ENTRY_KIND_UNSPECIFIED:
			return errors.New("unspecified IngestBatch_EntryKind")
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

	m.mu.RLock()
	defer m.mu.RUnlock()

	require.Len(m.t, m.synced, len(keys))
	for _, k := range keys {
		if _, ok := m.synced[string(k)]; !ok {
			return false
		}
	}

	return true
}

func TestHubLog(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	startDate, err := time.Parse(time.RFC3339, "2021-01-01T10:00:00Z")
	require.NoError(t, err)

	// We use two streams (access + decision log scans). Each independent stream ends up with a partial page, therefore
	// we treat each batch separately (hence the /2 -> *2 below).
	wantNumBatches := int(math.Ceil((numRecords/2)/float64(batchSize))) * 2

	t.Run("insertsDeletesKeys", func(t *testing.T) {
		db, syncer := initDB(t)
		t.Cleanup(func() { _ = db.Close() })

		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(nil)
		loadedKeys := loadData(t, db, startDate)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.True(c, syncer.hasKeys(loadedKeys), "keys should have been synced")
			assert.Empty(c, getLocalKeys(t, db), "keys should have been deleted")
		}, 1*time.Second, 50*time.Millisecond)

		t.Run("filter", func(t *testing.T) {
			for _, e := range syncer.entries {
				switch v := e.Entry.(type) {
				case *logsv1.IngestBatch_Entry_AccessLogEntry:
					require.Zero(t, v.AccessLogEntry.Peer.Address)
				case *logsv1.IngestBatch_Entry_DecisionLogEntry:
					require.Zero(t, v.DecisionLogEntry.Peer.Address)
				}
			}
		})
	})

	t.Run("partiallyDeletesBeforeError", func(t *testing.T) {
		db, syncer := initDB(t)
		initialNBatches := int(math.Ceil(float64(wantNumBatches) * 0.2))

		// Server responds with unrecoverable error after first N pages
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(nil).Times(initialNBatches)
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(errors.New("some error"))

		loadData(t, db, startDate)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			haveLocalKeys := getLocalKeys(t, db)
			assert.Less(c, len(haveLocalKeys), numRecords)
		}, 1*time.Second, 50*time.Millisecond)
	})

	t.Run("nonDeletedOnError", func(t *testing.T) {
		db, syncer := initDB(t)

		// Server is down
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(errors.New("some error"))

		loadData(t, db, startDate)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			haveLocalKeys := getLocalKeys(t, db)
			assert.Equal(c, len(haveLocalKeys), numRecords)
		}, 1*time.Second, 50*time.Millisecond)
	})

	t.Run("deletesSyncKeysAfterBackoff", func(t *testing.T) {
		db, syncer := initDB(t)
		initialNBatches := int(math.Ceil(float64(wantNumBatches) * 0.2))

		// Server responds with backoff after first N pages
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(nil).Times(initialNBatches)
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(hub.ErrIngestBackoff{
			Backoff: 0,
		}).Twice() // two concurrent streams receive the same backoff response
		syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(nil)

		loadedKeys := loadData(t, db, startDate)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.True(c, syncer.hasKeys(loadedKeys), "keys should have been synced")
			assert.Empty(c, getLocalKeys(t, db), "keys should have been deleted")
		}, 1*time.Second, 50*time.Millisecond)
	})
}

func initDB(t *testing.T) (*hub.Log, *mockSyncer) {
	t.Helper()

	conf := &hub.Conf{
		Ingest: hub.IngestConf{
			MaxBatchSize:     batchSize,
			MinFlushInterval: flushInterval,
			FlushTimeout:     1 * time.Second,
			NumGoRoutines:    8,
		},
		Mask: hub.MaskConf{
			Peer: []string{"address"},
		},
		Conf: local.Conf{
			StoragePath:     t.TempDir(),
			RetentionPeriod: 24 * time.Hour,
			Advanced: local.AdvancedConf{
				BufferSize:    1,
				MaxBatchSize:  32,
				FlushInterval: flushInterval,
			},
		},
	}

	syncer := newMockSyncer(t)
	decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&audit.Conf{})
	db, err := hub.NewLog(conf, decisionFilter, syncer, zap.L().Named("auditlog"))
	require.NoError(t, err)

	require.Equal(t, hub.Backend, db.Backend())
	require.True(t, db.Enabled())
	return db, syncer
}

func TestHubLogWithDecisionLogFilter(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	confWrapper, err := config.WrapperFromMap(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"decisionLogFilters": map[string]any{
				"checkResources": map[string]any{
					"ignoreAllowAll": true,
				},
			},
			"backend": "hub",
			"hub": map[string]any{
				"storagePath": t.TempDir(),
				"advanced": map[string]any{
					"bufferSize": 1,
					"gcInterval": 0,
				},
				"ingest": map[string]any{
					"maxBatchSize":     batchSize,
					"minFlushInterval": "2s",
					"flushTimeout":     "1s",
				},
			},
		},
	})
	require.NoError(t, err)

	var auditConf audit.Conf
	require.NoError(t, confWrapper.GetSection(&auditConf))

	var hubConf hub.Conf
	require.NoError(t, confWrapper.GetSection(&hubConf))
	hubConf.Ingest.MinFlushInterval = flushInterval
	hubConf.Advanced.FlushInterval = flushInterval

	decisionFilter := audit.NewDecisionLogEntryFilterFromConf(&auditConf)
	syncer := newMockSyncer(t)
	db, err := hub.NewLog(&hubConf, decisionFilter, syncer, zap.L().Named("auditlog"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	require.Equal(t, hub.Backend, db.Backend())
	require.True(t, db.Enabled())

	startDate, err := time.Parse(time.RFC3339, "2021-01-01T10:00:00Z")
	require.NoError(t, err)

	syncer.EXPECT().Sync(mock.Anything, mock.AnythingOfType("*logsv1.IngestBatch")).Return(nil)
	loadedKeys := loadData(t, db, startDate)
	// There should be no decision logs to sync. Only the access logs are synced.
	wantNumRecords := numRecords / 2

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, syncer.hasKeys(loadedKeys[:wantNumRecords]), "keys should have been synced")
	}, 1*time.Second, 50*time.Millisecond)
}

func getLocalKeys(t *testing.T, db *hub.Log) [][]byte {
	t.Helper()

	keys := [][]byte{}
	err := db.Db.View(func(txn *badgerv4.Txn) error {
		opts := badgerv4.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(hub.SyncStatusPrefix); it.ValidForPrefix(hub.SyncStatusPrefix); it.Next() {
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

func loadData(t *testing.T, db *hub.Log, startDate time.Time) [][]byte {
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
		syncKeys[i] = local.GenKey(hub.AccessSyncPrefix, callID)
		syncKeys[i+(numRecords/2)] = local.GenKey(hub.DecisionSyncPrefix, callID)

		err = db.WriteAccessLogEntry(ctx, mkAccessLogEntry(t, id, i, ts))
		require.NoError(t, err)

		err = db.WriteDecisionLogEntry(ctx, mkDecisionLogEntry(t, id, i, ts))
		require.NoError(t, err)
	}

	time.Sleep(flushInterval * 20)
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
			Peer: &auditv1.Peer{
				Address: "1.1.1.1",
			},
			Method: &auditv1.DecisionLogEntry_CheckResources_{
				CheckResources: &auditv1.DecisionLogEntry_CheckResources{
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
				},
			},
		}, nil
	}
}
