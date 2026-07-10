// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
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
