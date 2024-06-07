// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package rolepolicy

import "github.com/kelindar/bitmap"

type Manager interface {
	GetIndex(string) uint32
	OnesMask() []uint64
}

func NewNopManager() NopManager {
	return NopManager{}
}

type NopManager struct{}

func (n NopManager) GetIndex(string) uint32 {
	return 0
}

func (n NopManager) OnesMask() []uint64 {
	return []uint64{}
}

type manager struct {
	actionIndexes map[string]uint32
	onesMask      []uint64
}

func NewManager(actionIndexes map[string]uint32) Manager {
	if actionIndexes == nil {
		actionIndexes = make(map[string]uint32)
	}

	var mask bitmap.Bitmap
	mask.Grow(uint32(len(actionIndexes)))
	mask.Ones()

	return &manager{
		actionIndexes: actionIndexes,
		onesMask:      mask,
	}
}

func (m *manager) GetIndex(action string) uint32 {
	return m.actionIndexes[action]
}

func (m *manager) OnesMask() []uint64 {
	return m.onesMask
}
