// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

import (
	"fmt"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
)

var ruleTableRulesField = new(runtimev1.RuleTable).ProtoReflect().Descriptor().Fields().ByName("rules").Number()

// AppendRuleRowRecord replicates protobuf marshalling of a single
// runtimev1.RuleTable_RuleRow as it is done by the (*RuleTable).MarshalToVT
// method. It can be used to marshall rows separately from the rest of the
// RuleTable.
func AppendRuleRowRecord(buf []byte, row *runtimev1.RuleTable_RuleRow) ([]byte, error) {
	buf = protowire.AppendTag(buf, ruleTableRulesField, protowire.BytesType)
	size := row.SizeVT()
	buf = protowire.AppendVarint(buf, uint64(size))
	offset := len(buf)
	buf = slices.Grow(buf, size)[: offset+size : offset+size]
	if _, err := row.MarshalToVT(buf[offset:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// ScanRuleTable walks the top-level records of a protobuf-encoded
// runtimev1.RuleTable without unmarshalling it and invokes the callbacks.
// onRow is a callback function invoked for each entry of the `rules` field.
// Its arguments:
// n - 0-based ordinal of the entry,
// record - the full record bytes (tag, length and payload),
// payload - payload itself.
// onOther is a callback function invoked for each (top) field other than `rules`.
// Its argument:
// record - the full record bytes (tag, length and payload).
func ScanRuleTable(data []byte, onRow func(n int, record, payload []byte) error, onOther func(record []byte) error) error {
	n := 0
	for len(data) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(data)
		if tagLen < 0 {
			return fmt.Errorf("malformed rule table: %w", protowire.ParseError(tagLen))
		}

		if num == ruleTableRulesField {
			if typ != protowire.BytesType {
				return fmt.Errorf("malformed rule table: rules record %d has wire type %d, want %d", n, typ, protowire.BytesType)
			}

			payload, valLen := protowire.ConsumeBytes(data[tagLen:])
			if valLen < 0 {
				return fmt.Errorf("malformed rule table: rules record %d: %w", n, protowire.ParseError(valLen))
			}

			if err := onRow(n, data[:tagLen+valLen], payload); err != nil {
				return err
			}
			n++
			data = data[tagLen+valLen:]
			continue
		}

		valLen := protowire.ConsumeFieldValue(num, typ, data[tagLen:])
		if valLen < 0 {
			return fmt.Errorf("malformed rule table: field %d: %w", num, protowire.ParseError(valLen))
		}

		if err := onOther(data[:tagLen+valLen]); err != nil {
			return err
		}
		data = data[tagLen+valLen:]
	}

	return nil
}
