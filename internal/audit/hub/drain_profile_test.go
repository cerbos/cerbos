// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !race

package hub

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

type countingSyncer struct {
	mu           sync.Mutex
	attempts     int
	entriesTotal int
	bytesTotal   int
	marshalWire  bool
}

func (s *countingSyncer) Sync(_ context.Context, batch *logsv1.IngestBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	s.entriesTotal += len(batch.Entries)
	if s.marshalWire {
		wire, err := batch.MarshalVT()
		if err != nil {
			return err
		}
		s.bytesTotal += len(wire)
	} else {
		s.bytesTotal += batch.SizeVT()
	}
	return nil
}

func (s *countingSyncer) stats() (attempts, entries, bytes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts, s.entriesTotal, s.bytesTotal
}

func newProfileLog(t *testing.T, syncer IngestSyncer) *Log {
	t.Helper()

	conf := &Conf{
		Ingest: IngestConf{
			MaxBatchSizeBytes: 4 * 1024 * 1024, // production default
			MinFlushInterval:  time.Hour,       // keep the background loop quiet
			FlushTimeout:      5 * time.Second,
			NumGoRoutines:     4,
		},
	}
	conf.StoragePath = t.TempDir()
	conf.RetentionPeriod = 24 * time.Hour
	conf.Advanced = local.AdvancedConf{
		BufferSize:    4096,
		MaxBatchSize:  1024,
		FlushInterval: 100 * time.Millisecond,
	}

	log, err := NewLog(conf, nil, syncer, zap.NewNop(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = log.Close() })
	return log
}

// writeBacklog writes n access and n decision entries (~1KB serialized each)
// and flushes them to badger.
func writeBacklog(t *testing.T, log *Log, n int) {
	t.Helper()

	ctx := context.Background()
	pad := strings.Repeat("x", 700)
	start := time.Now().Add(-time.Hour)
	for i := range n {
		ts := start.Add(time.Duration(i) * time.Millisecond)
		id, err := audit.NewIDForTime(ts)
		require.NoError(t, err)

		require.NoError(t, log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId:    string(id),
				Timestamp: timestamppb.New(ts),
				Peer:      &auditv1.Peer{Address: "1.1.1.1"},
				Metadata:  map[string]*auditv1.MetaValues{"pad": {Values: []string{pad}}},
				Method:    "/cerbos.svc.v1.CerbosService/Check",
			}, nil
		}))

		require.NoError(t, log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
			return &auditv1.DecisionLogEntry{
				CallId:    string(id),
				Timestamp: timestamppb.New(ts),
				Peer:      &auditv1.Peer{Address: "1.1.1.1"},
				Method: &auditv1.DecisionLogEntry_CheckResources_{
					CheckResources: &auditv1.DecisionLogEntry_CheckResources{
						Inputs: []*enginev1.CheckInput{{
							RequestId: string(id),
							Resource:  &enginev1.Resource{Kind: "test:kind", Id: pad},
							Principal: &enginev1.Principal{Id: "test", Roles: []string{"a", "b"}},
							Actions:   []string{"a1", "a2"},
						}},
						Outputs: []*enginev1.CheckOutput{{
							RequestId:  string(id),
							ResourceId: "test",
							Actions: map[string]*enginev1.CheckOutput_ActionEffect{
								"a1": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
								"a2": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
							},
						}},
					},
				},
			}, nil
		}))
	}
	log.ForceWrite()
}

func countKeys(t *testing.T, db *badgerv4.DB, prefix []byte) int {
	t.Helper()

	n := 0
	require.NoError(t, db.View(func(txn *badgerv4.Txn) error {
		opts := badgerv4.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			n++
		}
		return nil
	}))
	return n
}

func timeCycles(t *testing.T, log *Log, n int) time.Duration {
	t.Helper()

	start := time.Now()
	for range n {
		require.NoError(t, log.streamLogs())
	}
	return time.Since(start) / time.Duration(n)
}

func procStatusKB(t *testing.T, field string) uint64 {
	t.Helper()

	data, err := os.ReadFile("/proc/self/status")
	require.NoError(t, err)
	for line := range strings.Lines(string(data)) {
		if rest, ok := strings.CutPrefix(line, field+":"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			require.NoError(t, err)
			return kb << 10
		}
	}
	t.Fatalf("field %s not found in /proc/self/status", field)
	return 0
}

func resetPeakRSS(t *testing.T) {
	t.Helper()

	require.NoError(t, os.WriteFile("/proc/self/clear_refs", []byte("5"), 0), "cannot reset VmHWM")
}

// TestCatchupDrainProfile measures the catch-up path.
func TestCatchupDrainProfile(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip()
	}

	const (
		numRecords  = 100_000 // per kind
		emptyCycles = 20
	)

	syncer := &countingSyncer{marshalWire: os.Getenv("CERBOS_AUDIT_WIRE") != ""}
	log := newProfileLog(t, syncer)

	emptyCycleBefore := timeCycles(t, log, emptyCycles)

	preloadStart := time.Now()
	writeBacklog(t, log, numRecords)
	t.Logf("preloaded %d entries in %s", 2*numRecords, time.Since(preloadStart).Round(time.Millisecond))

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	resetPeakRSS(t)
	rssBefore := procStatusKB(t, "VmRSS")

	drainStart := time.Now()
	require.NoError(t, log.streamLogs(), "drain cycle must succeed")
	drainDur := time.Since(drainStart)

	peakRSS := procStatusKB(t, "VmHWM")

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	rssAfter := procStatusKB(t, "VmRSS")

	require.Zero(t, countKeys(t, log.Db, SyncStatusPrefix), "all sync markers must be drained")

	emptyCycleAfter := timeCycles(t, log, emptyCycles)

	attempts, entriesTotal, bytesTotal := syncer.stats()
	t.Logf("drained %d entries (%d MB serialized) in %s: %.0f entries/s, %.1f MB/s",
		entriesTotal, bytesTotal>>20, drainDur.Round(time.Millisecond),
		float64(entriesTotal)/drainDur.Seconds(), float64(bytesTotal)/(1<<20)/drainDur.Seconds())
	t.Logf("sync attempts: %d (avg entries/batch: %d, avg batch bytes: %d)",
		attempts, entriesTotal/attempts, bytesTotal/attempts)
	t.Logf("allocated bytes/entry drained: %d (total %d MB)",
		(after.TotalAlloc-before.TotalAlloc)/uint64(entriesTotal), (after.TotalAlloc-before.TotalAlloc)>>20) //nolint:gosec
	t.Logf("GC runs during drain: %d, total GC pause: %s",
		after.NumGC-before.NumGC, time.Duration(after.PauseTotalNs-before.PauseTotalNs)) //nolint:gosec
	t.Logf("heap in use (post-GC): before=%d MB after=%d MB",
		before.HeapInuse>>20, after.HeapInuse>>20)
	t.Logf("RSS: before=%d MB after=%d MB, peak (VmHWM, drain)=%d MB",
		rssBefore>>20, rssAfter>>20, peakRSS>>20)
	t.Logf("empty sync cycle: before backlog=%s, after drain (scanning across %d tombstoned markers)=%s",
		emptyCycleBefore, 2*numRecords, emptyCycleAfter)
}
