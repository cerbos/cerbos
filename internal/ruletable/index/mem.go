package index

import (
	"context"
	"maps"

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
	m map[string]*rowSet
}

func newMemLiteralMap() *memLiteralMap {
	return &memLiteralMap{
		make(map[string]*rowSet),
	}
}

func (lm *memLiteralMap) set(_ context.Context, k string, rs *rowSet) error {
	lm.m[k] = rs
	return nil
}

func (lm *memLiteralMap) get(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	res := make(map[string]*rowSet)
	for _, k := range keys {
		if v, ok := lm.m[k]; ok {
			// return a copy
			res[k] = newRowSet().unionWith(v)
		}
	}
	return res, nil
}

func (lm *memLiteralMap) getAll(context.Context) (map[string]*rowSet, error) {
	return maps.Clone(lm.m), nil
}

type memGlobMap struct {
	m *util.GlobMap[*rowSet]
}

func newMemGlobMap() *memGlobMap {
	return &memGlobMap{
		util.NewGlobMap(make(map[string]*rowSet)),
	}
}

func (gl *memGlobMap) set(_ context.Context, k string, rs *rowSet) error {
	gl.m.Set(k, rs)
	return nil
}

func (gl *memGlobMap) getWithLiteral(_ context.Context, keys ...string) (map[string]*rowSet, error) {
	res := make(map[string]*rowSet)
	for _, k := range keys {
		if v, ok := gl.m.GetWithLiteral(k); ok {
			// copy
			res[k] = newRowSet().unionWith(v)
		}
	}
	return res, nil
}

func (gl *memGlobMap) getMerged(_ context.Context, keys ...string) (map[string]*rowSet, error) {
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

func (gl *memGlobMap) getAll(context.Context) (map[string]*rowSet, error) {
	return gl.m.GetAll(), nil
}
