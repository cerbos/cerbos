// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

import (
	internalruletable "github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/index"
)

type (
	Binding        = index.Binding
	FunctionalCore = index.FunctionalCore
	Index          = index.Index
	Option         = index.Option
	RowParams      = index.RowParams
)

var (
	New       = index.New
	Unmarshal = index.Unmarshal
)

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
	return internalruletable.ScanRuleTable(data, onRow, onOther)
}
