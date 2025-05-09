// Copyright 2021-2025 Zenauth Ltd.
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
	"google.golang.org/protobuf/types/known/structpb"
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
			a := e.GetAccessLogEntry()
			key = keyFromCallID(m.t, a.CallId, a.SizeVT(), hub.AccessSyncPrefix)
		case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
			d := e.GetDecisionLogEntry()
			key = keyFromCallID(m.t, d.CallId, d.SizeVT(), hub.DecisionSyncPrefix)
		case logsv1.IngestBatch_ENTRY_KIND_UNSPECIFIED:
			return errors.New("unspecified IngestBatch_EntryKind")
		}

		m.synced[string(key)] = struct{}{}
	}

	return nil
}

func keyFromCallID(t *testing.T, callID string, size int, prefix []byte) []byte {
	t.Helper()

	callIDbytes, err := audit.ID(callID).Repr()
	require.NoError(t, err)

	return local.GenKeyWithByteSize(prefix, callIDbytes, size)
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

	return initDBWithBatchCfg(t, batchSize, 1048576)
}

func initDBWithBatchCfg(t *testing.T, maxBatchSize, maxBatchSizeBytes uint) (*hub.Log, *mockSyncer) {
	t.Helper()

	conf := &hub.Conf{
		Ingest: hub.IngestConf{
			MaxBatchSize:      maxBatchSize,
			MaxBatchSizeBytes: maxBatchSizeBytes,
			MinFlushInterval:  flushInterval,
			FlushTimeout:      1 * time.Second,
			NumGoRoutines:     8,
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

func TestSizeBasedBatching(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	startDate, err := time.Parse(time.RFC3339, "2021-01-01T10:00:00Z")
	require.NoError(t, err)

	t.Run("createsBatchesBySize", func(t *testing.T) {
		var maxBatchSizeBytes uint = 500 // single record in the realms of ~100-200 bytes
		db, syncer := initDBWithBatchCfg(t, numRecords, maxBatchSizeBytes)
		t.Cleanup(func() { _ = db.Close() })

		// Count the number of Sync calls to verify multiple batches are created
		syncCalls := 0
		syncer.EXPECT().Sync(mock.Anything, mock.MatchedBy(func(batch *logsv1.IngestBatch) bool {
			syncCalls++
			return batch.SizeVT() <= int(maxBatchSizeBytes)
		})).Return(nil)

		loadedKeys := loadData(t, db, startDate)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, syncCalls, 1, "should have created multiple batches due to size limits")
			assert.True(c, syncer.hasKeys(loadedKeys), "keys should have been synced")
			assert.Empty(c, getLocalKeys(t, db), "keys should have been deleted")
		}, 1*time.Second, 50*time.Millisecond)
	})

	t.Run("handlesOversizedEntries", func(t *testing.T) {
		maxBatchSizeBytes := 1024
		db, syncer := initDBWithBatchCfg(t, numRecords, uint(maxBatchSizeBytes))
		t.Cleanup(func() { _ = db.Close() })

		ctx := t.Context()

		// Create an ID for regular entry
		id, err := audit.NewID()
		require.NoError(t, err)

		// First add a regular entry
		normalEntry, err := mkAccessLogEntry(t, id, 1, startDate)()
		require.NoError(t, err)

		wrapped := func() (*auditv1.AccessLogEntry, error) {
			return normalEntry, err
		}

		err = db.WriteAccessLogEntry(ctx, wrapped)
		require.NoError(t, err)

		// Create a different ID for the oversized entry
		oversizeID, err := audit.NewID()
		require.NoError(t, err)

		// Add an oversized entry with lots of metadata to exceed the batch size
		nValues := 1000
		veryLargeMetadata := map[string]*auditv1.MetaValues{
			"large": {Values: make([]string, nValues)},
		}
		for i := range nValues {
			veryLargeMetadata["large"].Values[i] = "value" + strconv.Itoa(i)
		}

		err = db.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
			return &auditv1.DecisionLogEntry{
				CallId:    string(oversizeID),
				Timestamp: timestamppb.New(startDate),
				Peer: &auditv1.Peer{
					Address: "1.1.1.1",
				},
				Metadata: veryLargeMetadata,
				Method: &auditv1.DecisionLogEntry_CheckResources_{
					CheckResources: &auditv1.DecisionLogEntry_CheckResources{
						Inputs: []*enginev1.CheckInput{
							{
								RequestId: "1",
								Resource: &enginev1.Resource{
									Kind:          "leave_request",
									PolicyVersion: "default",
									Id:            "lr1",
									Attr: map[string]*structpb.Value{
										"foo": structpb.NewBoolValue(true),
										"bar": structpb.NewStringValue("barVal"),
									},
								},
								Principal: &enginev1.Principal{
									Id:            "p1",
									PolicyVersion: "default",
									Roles:         []string{"user"},
									Attr: map[string]*structpb.Value{
										"foo": structpb.NewBoolValue(true),
										"bar": structpb.NewStringValue("barVal"),
									},
								},
								Actions: []string{"view", "create", "delete"},
								AuxData: &enginev1.AuxData{},
							},
						},
						Outputs: []*enginev1.CheckOutput{
							{
								RequestId:  "1",
								ResourceId: "lr1",
								Actions: map[string]*enginev1.CheckOutput_ActionEffect{
									"view": &enginev1.CheckOutput_ActionEffect{
										Effect: effectv1.Effect_EFFECT_ALLOW,
										Policy: "resource.test.v1",
									},
									"create": &enginev1.CheckOutput_ActionEffect{
										Effect: effectv1.Effect_EFFECT_ALLOW,
										Policy: "resource.test.v1",
									},
									"delete": &enginev1.CheckOutput_ActionEffect{
										Effect: effectv1.Effect_EFFECT_DENY,
										Policy: "resource.test.v1",
									},
								},
								EffectiveDerivedRoles: []string{"derived_admin"},
								Outputs: []*enginev1.OutputEntry{
									{
										Src: "resource.test.v1#some_rule",
										Val: &structpb.Value{
											Kind: &structpb.Value_BoolValue{
												BoolValue: true,
											},
										},
									},
								},
							},
						},
					},
				},
			}, nil
		})
		require.NoError(t, err)

		syncer.EXPECT().Sync(mock.Anything, mock.Anything).Twice().Return(nil)

		// Verify all keys are deleted after processing
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Empty(c, getLocalKeys(t, db), "keys should have been deleted")
		}, 1*time.Second, 50*time.Millisecond)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			require.Len(c, syncer.entries, 2)

			var al *auditv1.AccessLogEntry
			var dl *auditv1.DecisionLogEntry
			switch syncer.entries[0].Entry.(type) {
			case *logsv1.IngestBatch_Entry_AccessLogEntry:
				al = syncer.entries[0].GetAccessLogEntry()
				dl = syncer.entries[1].GetDecisionLogEntry()
			case *logsv1.IngestBatch_Entry_DecisionLogEntry:
				dl = syncer.entries[0].GetDecisionLogEntry()
				al = syncer.entries[1].GetAccessLogEntry()
			}

			require.NotNil(c, al)
			require.NotNil(c, dl)

			require.Equal(c, al.CallId, string(id))
			// only filtered by the custom filter
			require.Empty(c, al.Peer.Address)
			// bypasses oversized filter
			require.NotEmpty(c, al.Metadata)

			require.Equal(c, dl.CallId, string(oversizeID))
			// custom filter
			require.Empty(c, dl.Peer)
			require.Empty(c, dl.Metadata)

			cr := dl.GetCheckResources()
			require.Empty(c, cr.Inputs[0].Actions)
			require.Empty(c, cr.Inputs[0].AuxData)

			require.NotEmpty(c, cr.Inputs[0].Resource.Kind)
			require.Empty(c, cr.Inputs[0].Resource.Attr)

			require.NotEmpty(c, cr.Inputs[0].Principal.Id)
			require.Empty(c, cr.Inputs[0].Principal.Attr)

			ef, exists := cr.Outputs[0].Actions["create"]
			require.True(c, exists)
			require.Equal(c, ef.Effect, effectv1.Effect_EFFECT_ALLOW)

			require.Empty(c, cr.Outputs[0].EffectiveDerivedRoles)
			require.Empty(c, cr.Outputs[0].Outputs)

			require.LessOrEqual(c, dl.SizeVT(), maxBatchSizeBytes-hub.BatchSizeToleranceBytes)
		}, 1*time.Second, 50*time.Millisecond)
	})
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

	ctx := t.Context()
	syncKeys := make([][]byte, numRecords)
	for i := range numRecords / 2 {
		ts := startDate.Add(time.Duration(i) * time.Second)
		id, err := audit.NewIDForTime(ts)
		require.NoError(t, err)

		callID, err := audit.ID(string(id)).Repr()
		require.NoError(t, err)

		accessLogEntry, err := mkAccessLogEntry(t, id, i, ts)()
		require.NoError(t, err)
		accessLogEntryMaker := func() (*auditv1.AccessLogEntry, error) {
			return accessLogEntry, nil
		}

		decisionLogEntry, err := mkDecisionLogEntry(t, id, i, ts)()
		require.NoError(t, err)
		decisionLogEntryMaker := func() (*auditv1.DecisionLogEntry, error) {
			return decisionLogEntry, nil
		}

		err = db.WriteAccessLogEntry(ctx, accessLogEntryMaker)
		require.NoError(t, err)

		err = db.WriteDecisionLogEntry(ctx, decisionLogEntryMaker)
		require.NoError(t, err)

		// We insert decision sync logs in the latter half as this is the same
		// order that Badger retrieves keys from the LSM.
		// Key gen needs to follow on from the calls to `Write*LogEntry` as filtering occurs
		// inside those calls, and we need the size of the stored log.
		syncKeys[i] = local.GenKeyWithByteSize(hub.AccessSyncPrefix, callID, accessLogEntry.SizeVT())
		syncKeys[i+(numRecords/2)] = local.GenKeyWithByteSize(hub.DecisionSyncPrefix, callID, decisionLogEntry.SizeVT())
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
