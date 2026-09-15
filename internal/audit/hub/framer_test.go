// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

// TestRawFrameEquivalence checks the contract between batchFramer's hand-rolled
// wire format and the generated marshalers.
func TestRawFrameEquivalence(t *testing.T) {
	ts := time.Now()
	access := &auditv1.AccessLogEntry{
		CallId:    "access-call",
		Timestamp: timestamppb.New(ts),
		Peer:      &auditv1.Peer{Address: "1.1.1.1"},
		Metadata:  map[string]*auditv1.MetaValues{"k": {Values: []string{"v1", "v2"}}},
		Method:    "/cerbos.svc.v1.CerbosService/Check",
	}
	decision := &auditv1.DecisionLogEntry{
		CallId:    "decision-call",
		Timestamp: timestamppb.New(ts),
		Peer:      &auditv1.Peer{Address: "1.1.1.1"},
	}

	rawAccess, err := access.MarshalVT()
	require.NoError(t, err)
	rawDecision, err := decision.MarshalVT()
	require.NoError(t, err)

	typed := &logsv1.IngestBatch{
		Id: "batch-id",
		Entries: []*logsv1.IngestBatch_Entry{
			{
				Kind:      logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG,
				Entry:     &logsv1.IngestBatch_Entry_AccessLogEntry{AccessLogEntry: access},
				Timestamp: access.Timestamp,
			},
			{
				Kind:      logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
				Entry:     &logsv1.IngestBatch_Entry_DecisionLogEntry{DecisionLogEntry: decision},
				Timestamp: decision.Timestamp,
			},
		},
	}

	f := &batchFramer{}
	f.beginBatch(typed.Id)
	f.add(logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, rawAccess)
	f.add(logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG, rawDecision)
	require.Equal(t, 2, f.count)

	typedWire, err := typed.MarshalVT()
	require.NoError(t, err)
	require.Equal(t, typedWire, f.wire(), "framed bytes must be byte-identical to MarshalVT of the typed batch")

	decoded := &logsv1.IngestBatch{}
	require.NoError(t, decoded.UnmarshalVT(f.wire()))
	require.True(t, proto.Equal(typed, decoded), "framed bytes must decode to the same message as the typed path")

	require.Equal(t, typed.Entries[0].SizeVT(), getEntrySize(logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, rawAccess))
	require.Equal(t, typed.Entries[1].SizeVT(), getEntrySize(logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG, rawDecision))
}

// TestRawFrameRollRestore checks that rolling the last entry out of a batch
// and restoring it into the next one leaves both batches with the same wire
// bytes as reference batches built from scratch with the same entries.
func TestRawFrameRollRestore(t *testing.T) {
	ts := time.Now()
	mkRaw := func(callID string) []byte {
		raw, err := (&auditv1.AccessLogEntry{
			CallId:    callID,
			Timestamp: timestamppb.New(ts),
			Peer:      &auditv1.Peer{Address: "1.1.1.1"},
		}).MarshalVT()
		require.NoError(t, err)
		return raw
	}
	raw1 := mkRaw("call-1")
	raw2 := mkRaw("call-2")

	frame := func(id string, raws ...[]byte) []byte {
		f := &batchFramer{}
		f.beginBatch(id)
		for _, raw := range raws {
			f.add(logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, raw)
		}
		return append([]byte(nil), f.wire()...)
	}

	f := &batchFramer{}
	f.beginBatch("batch-a")
	f.add(logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, raw1)
	f.add(logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, raw2)

	f.rollLast()
	require.Equal(t, 1, f.count)
	require.Equal(t, frame("batch-a", raw1), f.wire())

	f.beginBatch("batch-b")
	f.restoreLast()
	require.Equal(t, 1, f.count)
	require.Equal(t, frame("batch-b", raw2), f.wire())

	// the restored entry must roll again, e.g. when it overflows the sole-entry batch
	f.add(logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, raw1)
	f.rollLast()
	require.Equal(t, 1, f.count)
	require.Equal(t, frame("batch-b", raw2), f.wire())
}

// TestRawFrameNoTimestamp checks that an entry without a timestamp is framed
// without a wrapper timestamp, matching the typed path's nil propagation.
func TestRawFrameNoTimestamp(t *testing.T) {
	bare := &auditv1.AccessLogEntry{CallId: "bare-call"}
	rawBare, err := bare.MarshalVT()
	require.NoError(t, err)

	f := &batchFramer{}
	f.beginBatch("batch-id")
	f.add(logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, rawBare)

	decoded := &logsv1.IngestBatch{}
	require.NoError(t, decoded.UnmarshalVT(f.wire()))
	require.Len(t, decoded.Entries, 1)
	require.Nil(t, decoded.Entries[0].Timestamp)
	require.True(t, proto.Equal(bare, decoded.Entries[0].GetAccessLogEntry()))
}
