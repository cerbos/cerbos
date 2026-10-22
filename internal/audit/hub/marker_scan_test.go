// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

// callIDSyncer records the call IDs of the access log entries it receives.
type callIDSyncer struct {
	callIDs []string
	mu      sync.Mutex
}

func (s *callIDSyncer) Sync(_ context.Context, batch []byte, _ int) error {
	ingestBatch := &logsv1.IngestBatch{}
	if err := ingestBatch.UnmarshalVT(batch); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range ingestBatch.Entries {
		s.callIDs = append(s.callIDs, e.GetAccessLogEntry().GetCallId())
	}
	return nil
}

// take returns the call IDs received since the previous call.
func (s *callIDSyncer) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	callIDs := s.callIDs
	s.callIDs = nil
	return callIDs
}

func TestMarkerScan(t *testing.T) {
	newLog := func(t *testing.T, syncer IngestSyncer) *Log {
		t.Helper()

		conf := &Conf{}
		conf.SetDefaults()
		conf.Ingest.MinFlushInterval = time.Hour // the test drives the sync runs
		conf.StoragePath = t.TempDir()
		conf.Advanced.GCInterval = 0 // ForceWrite deadlocks if the gc goroutine is running

		log, err := NewLog(conf, nil, syncer, zap.NewNop(), nil)
		require.NoError(t, err)
		return log
	}

	// write writes an access log entry with a call ID for ts and returns the ID.
	write := func(t *testing.T, log *Log, ts time.Time) string {
		t.Helper()

		id, err := audit.NewIDForTime(ts)
		require.NoError(t, err)
		require.NoError(t, log.WriteAccessLogEntry(t.Context(), func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{CallId: string(id), Timestamp: timestamppb.New(ts)}, nil
		}))
		log.ForceWrite()
		return string(id)
	}

	syncer := &callIDSyncer{}
	log := newLog(t, syncer)
	t.Cleanup(func() { _ = log.Close() })

	// Ship a marker, so that the next run resumes after it, then write a late
	// marker that sorts before the resume point and a marker that sorts after it.
	start := time.Now().Add(-time.Hour)
	shipped := write(t, log, start.Add(time.Minute))
	require.NoError(t, log.streamLogs(), "the first run walks the prefix")
	require.Equal(t, []string{shipped}, syncer.take())

	late := write(t, log, start)
	next := write(t, log, start.Add(2*time.Minute))
	require.NoError(t, log.streamLogs())
	require.Equal(t, []string{next}, syncer.take(), "a resumed run should skip the late marker")

	// The first run was run 0, so runs 1..11 resume and run 12 walks the prefix.
	for range fullMarkerScanEvery - 2 {
		require.NoError(t, log.streamLogs())
		require.Empty(t, syncer.take(), "a resumed run should skip the late marker")
	}

	require.NoError(t, log.streamLogs())
	require.Equal(t, []string{late}, syncer.take(), "the full scan should ship the late marker")
}
