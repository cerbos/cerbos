package index

import (
	"context"

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

func (lm *MemLiteralMap) get(_ context.Context, k string) (*rowSet, bool, error) {
	v, ok := lm.m[k]
	return v, ok, nil
}

func (lm *MemLiteralMap) getAll(context.Context) (map[string]*rowSet, error) {
	return lm.m, nil
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

func (gl *MemGlobMap) getWithLiteral(_ context.Context, k string) (*rowSet, bool, error) {
	rs, exists := gl.m.GetWithLiteral(k)
	return rs, exists, nil
}

func (gl *MemGlobMap) getMerged(_ context.Context, k string) (map[string]*rowSet, error) {
	return gl.m.GetMerged(k), nil
}

func (gl *MemGlobMap) getAll(context.Context) (map[string]*rowSet, error) {
	return gl.m.GetAll(), nil
}
