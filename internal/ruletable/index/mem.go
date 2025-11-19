// Copyright ((2021-2025)|(2025)) Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"sync"

	"github.com/cerbos/cerbos/internal/util"
)

const memNamespaceKey = "mem"

var (
	_ Index      = (*Mem)(nil)
	_ literalMap = (*memLiteralMap)(nil)
	_ globMap    = (*memGlobMap)(nil)
)

type Mem struct {
	namespace string
}

func NewMem() *Mem {
	return &Mem{namespace: memNamespaceKey}
}

func (m *Mem) getLiteralMap(string) literalMap {
	return newMemLiteralMap()
}

func (m *Mem) getGlobMap(string) globMap {
	return newMemGlobMap()
}

func (m *Mem) resolve(_ context.Context, rows []*Row) ([]*Row, error) {
	return rows, nil
}

type memLiteralMap struct {
	mu sync.RWMutex
	m  map[string]*rowSet
}

func newMemLiteralMap() *memLiteralMap {
	return &memLiteralMap{
		m: make(map[string]*rowSet),
	}
}

func (lm *memLiteralMap) set(_ context.Context, k string, rs *rowSet) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.m[k] = rs
	return nil
}

func (lm *memLiteralMap) get(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	res := make(map[string]*rowSet, len(keys))
	for _, k := range keys {
		if v, ok := lm.m[k]; ok {
			// return a copy to prevent external mutation of the index
			res[k] = newRowSet().unionWith(v)
		}
	}
	return res, nil
}

func (lm *memLiteralMap) getAll(context.Context) (map[string]*rowSet, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	res := make(map[string]*rowSet, len(lm.m))
	for k, v := range lm.m {
		res[k] = newRowSet().unionWith(v)
	}
	return res, nil
}

func (lm *memLiteralMap) delete(_ context.Context, keys ...string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for _, k := range keys {
		delete(lm.m, k)
	}
	return nil
}

type memGlobMap struct {
	mu sync.RWMutex
	m  *util.GlobMap[*rowSet]
}

func newMemGlobMap() *memGlobMap {
	return &memGlobMap{
		m: util.NewGlobMap(make(map[string]*rowSet)),
	}
}

func (gl *memGlobMap) set(_ context.Context, k string, rs *rowSet) error {
	gl.mu.Lock()
	defer gl.mu.Unlock()
	gl.m.Set(k, rs)
	return nil
}

func (gl *memGlobMap) getWithLiteral(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	gl.mu.RLock()
	defer gl.mu.RUnlock()

	res := make(map[string]*rowSet, len(keys))
	for _, k := range keys {
		if v, ok := gl.m.GetWithLiteral(k); ok {
			res[k] = newRowSet().unionWith(v)
		}
	}
	return res, nil
}

func (gl *memGlobMap) getMerged(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	gl.mu.RLock()
	defer gl.mu.RUnlock()

	res := make(map[string]*rowSet, len(keys))
	for _, k := range keys {
		rs := newRowSet()
		for _, s := range gl.m.GetMerged(k) {
			rs = rs.unionWith(s)
		}
		res[k] = rs
	}
	return res, nil
}

func (gl *memGlobMap) getAll(context.Context) (map[string]*rowSet, error) {
	gl.mu.RLock()
	defer gl.mu.RUnlock()

	raw := gl.m.GetAll()
	res := make(map[string]*rowSet, len(raw))
	for k, v := range raw {
		res[k] = newRowSet().unionWith(v)
	}
	return res, nil
}

func (gl *memGlobMap) delete(_ context.Context, keys ...string) error {
	gl.mu.Lock()
	defer gl.mu.Unlock()
	for _, k := range keys {
		gl.m.DeleteLiteral(k)
	}
	return nil
}
