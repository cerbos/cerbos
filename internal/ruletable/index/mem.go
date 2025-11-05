package index

import (
	"context"
	"maps"

	"github.com/cerbos/cerbos/internal/util"
)

const memNamespaceKey = "mem"

var (
	_ Index      = (*Mem)(nil)
	_ literalMap = (*MemLiteralMap)(nil)
	_ globMap    = (*MemGlobMap)(nil)
)

type Mem struct {
	namespace string
}

func NewMem() *Mem {
	return &Mem{namespace: memNamespaceKey}
}

func (m *Mem) getNamespace() string {
	return m.namespace
}

func (m *Mem) getLiteralMap(string) literalMap {
	return NewMemLiteralMap()
}

func (m *Mem) getGlobMap(string) globMap {
	return NewMemGlobMap()
}

type MemLiteralMap struct {
	m map[string]*rowSet
}

func NewMemLiteralMap() *MemLiteralMap {
	return &MemLiteralMap{
		make(map[string]*rowSet),
	}
}

func (lm *MemLiteralMap) set(_ context.Context, k string, rs *rowSet) error {
	lm.m[k] = rs
	return nil
}

func (lm *MemLiteralMap) get(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	res := make(map[string]*rowSet)
	for _, k := range keys {
		if v, ok := lm.m[k]; ok {
			// return a copy
			res[k] = newRowSet().unionWith(v)
		}
	}
	return res, nil
}

func (lm *MemLiteralMap) getAll(context.Context) (map[string]*rowSet, error) {
	return maps.Clone(lm.m), nil
}

type MemGlobMap struct {
	m *util.GlobMap[*rowSet]
}

func NewMemGlobMap() *MemGlobMap {
	return &MemGlobMap{
		util.NewGlobMap(make(map[string]*rowSet)),
	}
}

func (gl *MemGlobMap) set(_ context.Context, k string, rs *rowSet) error {
	gl.m.Set(k, rs)
	return nil
}

func (gl *MemGlobMap) getWithLiteral(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	res := make(map[string]*rowSet)
	for _, k := range keys {
		if v, ok := gl.m.GetWithLiteral(k); ok {
			// copy
			res[k] = newRowSet().unionWith(v)
		}
	}
	return res, nil
}

func (gl *MemGlobMap) getMerged(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	res := make(map[string]*rowSet)
	for _, k := range keys {
		rs := newRowSet()
		for _, s := range gl.m.GetMerged(k) {
			rs = rs.unionWith(s)
		}
		res[k] = rs
	}
	return res, nil
}

func (gl *MemGlobMap) getAll(context.Context) (map[string]*rowSet, error) {
	return gl.m.GetAll(), nil
}
