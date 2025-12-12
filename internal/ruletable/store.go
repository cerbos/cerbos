// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package ruletable

// RuleTableStore is implemented by stores that have pre-compiled rule tables.
type RuleTableStore interface {
	GetRuleTable() (*RuleTable, error)
}
