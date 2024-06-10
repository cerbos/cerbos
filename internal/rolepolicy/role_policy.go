// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package rolepolicy

import "github.com/kelindar/bitmap"

var _ Manager = (*NopManager)(nil)

type Manager interface {
	AddAction(string)
	GetActionIndex(string) int
	SetResource(string)
	GetAllResources() []string
	OnesMask() []uint64
}

func NewNopManager() NopManager {
	return NopManager{}
}

type NopManager struct{}

func (n NopManager) AddAction(string) {}

func (n NopManager) GetActionIndex(string) int {
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
	actionCnt     int
	actionIndexes map[string]int
	onesMask      bitmap.Bitmap
	resources     map[string]struct{}
}

func NewManager() Manager {
	return &manager{
		actionIndexes: make(map[string]int),
		resources:     make(map[string]struct{}),
	}
}

func (m *manager) AddAction(action string) {
	if _, ok := m.actionIndexes[action]; !ok {
		m.actionIndexes[action] = m.actionCnt
		m.actionCnt++
	}
}

func (m *manager) GetActionIndex(a string) int {
	idx, ok := m.actionIndexes[a]
	if !ok {
		return -1
	}

	return idx
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
	if m.actionCnt == m.onesMask.Count() {
		return m.onesMask
	}

	m.onesMask.Grow(uint32(m.actionCnt))
	m.onesMask.Ones()

	return m.onesMask
}
