// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package rolepolicy

var _ Manager = (*NopManager)(nil)

type Manager interface {
	AddAction(string)
	GetActionIndex(string) uint32
	SetResource(string)
	GetAllResources() []string
	OnesMask() []uint64
}

func NewNopManager() NopManager {
	return NopManager{}
}

// TODO(saml) is this implementation required?
type NopManager struct{}

func (n NopManager) AddAction(string) {}

func (n NopManager) GetActionIndex(string) uint32 {
	return 0
}

func (n NopManager) SetResource(string) {}

func (n NopManager) GetAllResources() []string {
	return []string{}
}

func (n NopManager) OnesMask() []uint64 {
	return []uint64{}
}

type manager struct {
	actionCnt     uint32
	actionIndexes map[string]uint32
	onesMask      []uint64
	resources     map[string]struct{}
}

func NewManager() Manager {
	return &manager{
		actionIndexes: make(map[string]uint32),
		resources:     make(map[string]struct{}),
	}
}

func (m *manager) AddAction(action string) {
	if _, ok := m.actionIndexes[action]; !ok {
		m.actionIndexes[action] = m.actionCnt
		m.actionCnt++
	}
}

func (m *manager) GetActionIndex(a string) uint32 {
	return m.actionIndexes[a]
}

func (m *manager) SetResource(name string) {
	if _, ok := m.resources[name]; !ok {
		m.resources[name] = struct{}{}
	}
}

func (m *manager) GetAllResources() []string {
	res := make([]string, len(m.resources))
	var i int
	for r := range m.resources {
		res[i] = r
		i++
	}
	return res
}

func (m *manager) OnesMask() []uint64 {
	return m.onesMask
}
