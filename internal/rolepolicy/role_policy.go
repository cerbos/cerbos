// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package rolepolicy

type Manager interface {
	GetIndex(string) uint32
	GetMap() map[string]uint32
}

func NewNopManager() NopManager {
	return NopManager{}
}

type NopManager struct{}

func (n NopManager) GetIndex(string) uint32 {
	return 0
}

func (n NopManager) GetMap() map[string]uint32 {
	return make(map[string]uint32)
}

type manager struct {
	actionIndexes map[string]uint32
}

// TODO(saml) rename to NewManager.
func NewManager(m map[string]uint32) Manager {
	if m == nil {
		m = make(map[string]uint32)
	}

	return &manager{
		actionIndexes: m,
	}
}

func (m *manager) GetIndex(action string) uint32 {
	return m.actionIndexes[action]
}

func (m *manager) GetMap() map[string]uint32 {
	return m.actionIndexes
}
