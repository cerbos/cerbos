// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

// batchFramer builds IngestBatch wire bytes directly from the protobuf-encoded
// entries stored in Badger, skipping the unmarshal/re-marshal round trip.
var (
	batchIDField      = fieldNumber(new(logsv1.IngestBatch), "id")
	batchEntriesField = fieldNumber(new(logsv1.IngestBatch), "entries")

	entryKindField      = fieldNumber(new(logsv1.IngestBatch_Entry), "kind")
	entryTimestampField = fieldNumber(new(logsv1.IngestBatch_Entry), "timestamp")
	entryAccessField    = fieldNumber(new(logsv1.IngestBatch_Entry), "access_log_entry")
	entryDecisionField  = fieldNumber(new(logsv1.IngestBatch_Entry), "decision_log_entry")

	accessTimestampField   = fieldNumber(new(auditv1.AccessLogEntry), "timestamp")
	decisionTimestampField = fieldNumber(new(auditv1.DecisionLogEntry), "timestamp")
)

func fieldNumber(m proto.Message, name protoreflect.Name) protowire.Number {
	fd := m.ProtoReflect().Descriptor().Fields().ByName(name)
	if fd == nil {
		panic(fmt.Sprintf("field %q not found in %s", name, m.ProtoReflect().Descriptor().FullName()))
	}
	return fd.Number()
}

// entryFields returns the field numbers that vary with the entry kind: the
// entry's own timestamp field (the fetch target) and the wrapper's oneof field.
func entryFields(kind logsv1.IngestBatch_EntryKind) (tsField, oneofField protowire.Number) {
	if kind == logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG {
		return decisionTimestampField, entryDecisionField
	}
	return accessTimestampField, entryAccessField
}

var framerPool = sync.Pool{New: func() any { return new(batchFramer) }}

type batchFramer struct {
	buf       []byte
	carry     []byte
	count     int
	lastStart int
}

func (f *batchFramer) beginBatch(batchID string) {
	f.buf = protowire.AppendTag(f.buf[:0], batchIDField, protowire.BytesType)
	f.buf = protowire.AppendString(f.buf, batchID)
	f.count = 0
}

func (f *batchFramer) add(kind logsv1.IngestBatch_EntryKind, raw []byte) {
	f.lastStart = len(f.buf)

	tsField, oneofField := entryFields(kind)
	ts, hasTS := fetchField(raw, tsField)

	f.buf = protowire.AppendTag(f.buf, batchEntriesField, protowire.BytesType)
	f.buf = protowire.AppendVarint(f.buf, uint64(entryWireSize(kind, ts, hasTS, len(raw), oneofField)))

	f.buf = protowire.AppendTag(f.buf, entryKindField, protowire.VarintType)
	f.buf = protowire.AppendVarint(f.buf, uint64(kind))

	if hasTS {
		f.buf = protowire.AppendTag(f.buf, entryTimestampField, protowire.BytesType)
		f.buf = protowire.AppendBytes(f.buf, ts)
	}

	f.buf = protowire.AppendTag(f.buf, oneofField, protowire.BytesType)
	f.buf = protowire.AppendBytes(f.buf, raw)

	f.count++
}

// wire returns the serialized IngestBatch accumulated so far. The slice is
// only valid until the next begin call.
func (f *batchFramer) wire() []byte {
	return f.buf
}

// size returns the exact wire size of the batch accumulated so far.
func (f *batchFramer) size() int {
	return len(f.buf)
}

// rollLast moves the most recently added entry out of the batch into a
// scratch buffer so the batch can be shipped without it. restoreLast puts it
// back into the batch started by the next beginBatch.
func (f *batchFramer) rollLast() {
	f.carry = append(f.carry[:0], f.buf[f.lastStart:]...)
	f.buf = f.buf[:f.lastStart]
	f.count--
}

func (f *batchFramer) restoreLast() {
	f.lastStart = len(f.buf)
	f.buf = append(f.buf, f.carry...)
	f.count++
}

// getEntrySize returns the wire size of the IngestBatch_Entry message that add
// would build around raw. This is the same value the typed unmarshal-wrap path
// would report via SizeVT.
func getEntrySize(kind logsv1.IngestBatch_EntryKind, raw []byte) int {
	tsField, oneofField := entryFields(kind)
	ts, hasTS := fetchField(raw, tsField)
	return entryWireSize(kind, ts, hasTS, len(raw), oneofField)
}

func entryWireSize(kind logsv1.IngestBatch_EntryKind, ts []byte, hasTS bool, rawLen int, oneofField protowire.Number) int {
	size := protowire.SizeTag(entryKindField) + protowire.SizeVarint(uint64(kind))
	if hasTS {
		size += protowire.SizeTag(entryTimestampField) + protowire.SizeBytes(len(ts))
	}
	return size + protowire.SizeTag(oneofField) + protowire.SizeBytes(rawLen)
}

// fetchField walks the top-level fields of a protobuf message and returns the
// payload of the first field with the given number, without decoding anything
// else.
func fetchField(buf []byte, target protowire.Number) ([]byte, bool) {
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, false
		}
		buf = buf[n:]

		if num == target && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return nil, false
			}
			return v, true
		}

		n = protowire.ConsumeFieldValue(num, typ, buf)
		if n < 0 {
			return nil, false
		}
		buf = buf[n:]
	}
	return nil, false
}
