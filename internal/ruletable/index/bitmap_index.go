// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

// bitmapIndex is the core in-memory bitmap index. Each binding gets a uint32 ID,
// and each (dimension, value) pair has a bitmap tracking which binding IDs
// have that value. Queries are flat bitmap AND operations.
type bitmapIndex struct {
	action             *globDimension
	coresBySum         map[uint64]*FunctionalCore // dedup behavioural part
	version            dimension[string]
	scope              dimension[string]
	role               *globDimension
	policyKind         dimension[policyv1.Kind]
	resource           *globDimension
	fqnBindings        fqnDimension
	principal          lazyDimension
	universe           *Bitmap
	allowActionsBitmap *Bitmap
	freeIDs            []uint32
	bindings           []*BindingHandle
	evalKeys           []EvaluationKeyTuple
}

// noEvalKey is the sentinel binding ID meaning "no evaluation key".
const noEvalKey = ^uint32(0)

func newBitmapIndex() *bitmapIndex {
	return &bitmapIndex{
		version:            newDimension[string](),
		scope:              newDimension[string](),
		role:               newGlobDimension(),
		action:             newGlobDimension(),
		resource:           newGlobDimension(),
		policyKind:         newDimension[policyv1.Kind](),
		principal:          newLazyDimension(),
		universe:           NewBitmap(),
		allowActionsBitmap: NewBitmap(),
		fqnBindings:        newFqnDimension(),
		coresBySum:         make(map[uint64]*FunctionalCore),
	}
}

// allocID returns a uint32 to use as a binding's bit position across all bitmaps.
// It reuses IDs freed by freeID so that repeated add/remove cycles don't grow the
// bindings slice or make the bitmaps increasingly sparse.
func (idx *bitmapIndex) allocID() uint32 {
	if len(idx.freeIDs) > 0 {
		id := idx.freeIDs[len(idx.freeIDs)-1]
		idx.freeIDs = idx.freeIDs[:len(idx.freeIDs)-1]
		return id
	}
	return uint32(len(idx.bindings))
}

func (idx *bitmapIndex) freeID(id uint32) {
	idx.bindings[id] = nil
	idx.evalKeys[id] = EvaluationKeyTuple{} // release the slot's interned handles
	idx.freeIDs = append(idx.freeIDs, id)
}

func (idx *bitmapIndex) evalKey(id uint32) EvaluationKeyTuple {
	if id == noEvalKey {
		return EvaluationKeyTuple{}
	}
	return idx.evalKeys[id]
}

// compact drops the per-bitmap capacity slack left by exponential growth across
// every persistent dimension bitmap. Called once after a full build/reload.
func (idx *bitmapIndex) compact() {
	for _, bm := range idx.version.m {
		bm.shrinkToFit()
	}
	for _, bm := range idx.scope.m {
		bm.shrinkToFit()
	}
	for _, bm := range idx.policyKind.m {
		bm.shrinkToFit()
	}
	idx.principal.compact()
	idx.role.compact()
	idx.action.compact()
	idx.resource.compact()
	idx.universe.shrinkToFit()
	idx.allowActionsBitmap.shrinkToFit()
}

func (idx *bitmapIndex) addBinding(b *BindingHandle, evalKey EvaluationKeyTuple) {
	id := idx.allocID()
	b.ID = id
	if int(id) < len(idx.bindings) {
		idx.bindings[id] = b
		idx.evalKeys[id] = evalKey
	} else {
		idx.bindings = append(idx.bindings, b)
		idx.evalKeys = append(idx.evalKeys, evalKey)
	}

	idx.universe.Add(id)

	// Scope "" is a valid literal (root scope), always indexed. Other dimensions
	// skip "" to avoid leaking empties from policies that don't participate in
	// them (e.g. principal-policy noop rows have no role/resource).
	idx.scope.Add(stringHandleValue(b.Scope), id)
	if b.Version != EmptyHandle {
		idx.version.Add(b.Version.Value(), id)
	}
	if b.Role != EmptyHandle {
		idx.role.Set(b.Role.Value(), id)
	}
	if b.Resource != EmptyHandle {
		idx.resource.Set(b.Resource.Value(), id)
	}

	if b.AllowActions != nil {
		idx.allowActionsBitmap.Add(id)
	} else if b.Action != EmptyHandle {
		idx.action.Set(b.Action.Value(), id)
	}

	idx.policyKind.Add(b.Core.PolicyKind, id)

	if b.Principal != EmptyHandle {
		idx.principal.Add(b.Principal.Value(), id)
	}

	idx.fqnBindings.Add(stringHandleValue(b.OriginFqn), id)
}

// removeBinding removes the binding from the slice and all dimension bitmaps,
// and returns the ID to the free list.
// It does NOT touch fqnBindings. That is managed by DeletePolicy, which needs
// to inspect fqnBindings across origins before deciding whether to remove the binding.
func (idx *bitmapIndex) removeBinding(b *BindingHandle) {
	id := b.ID

	idx.universe.Remove(id)
	idx.version.Remove(stringHandleValue(b.Version), id)
	idx.scope.Remove(stringHandleValue(b.Scope), id)

	idx.role.Remove(stringHandleValue(b.Role), id)
	idx.resource.Remove(stringHandleValue(b.Resource), id)

	if b.AllowActions != nil {
		idx.allowActionsBitmap.Remove(id)
	} else if b.Action != EmptyHandle {
		idx.action.Remove(b.Action.Value(), id)
	}

	idx.policyKind.Remove(b.Core.PolicyKind, id)
	idx.principal.Remove(stringHandleValue(b.Principal), id)

	idx.freeID(id)
}

func (idx *bitmapIndex) getBinding(id uint32) *BindingHandle {
	return idx.bindings[id]
}

// dimension is a thin wrapper around map[T]*Bitmap for exact-match dimensions.
type dimension[T comparable] struct {
	m map[T]*Bitmap
}

func newDimension[T comparable]() dimension[T] {
	return dimension[T]{m: make(map[T]*Bitmap)}
}

func (d dimension[T]) Add(key T, id uint32) {
	bm, ok := d.m[key]
	if !ok {
		bm = NewBitmap()
		d.m[key] = bm
	}
	bm.Add(id)
}

func (d dimension[T]) Remove(key T, id uint32) {
	if bm, ok := d.m[key]; ok {
		bm.Remove(id)
		if bm.IsEmpty() {
			delete(d.m, key)
		}
	}
}

func (d dimension[T]) Get(key T) (*Bitmap, bool) {
	bm, ok := d.m[key]
	return bm, ok
}

func (d dimension[T]) Delete(key T) {
	delete(d.m, key)
}

func (d dimension[T]) Keys() []T {
	keys := make([]T, 0, len(d.m))
	for k := range d.m {
		keys = append(keys, k)
	}
	return keys
}

// Query returns OR(d[k] for k in keys).
// The returned bitmap may alias a stored bitmap; callers must not mutate it.
func (d dimension[T]) Query(arena *bitmapArena, keys []T) *Bitmap {
	parts := make([]*Bitmap, 0, len(keys))
	for _, k := range keys {
		if bm, ok := d.m[k]; ok {
			parts = append(parts, bm)
		}
	}
	switch len(parts) {
	case 0:
		return emptyBitmap
	case 1:
		return parts[0]
	default:
		return arena.orInto(parts)
	}
}

// fqnDimension maps policy FQNs to the binding IDs that originated from them.
type fqnDimension struct {
	m map[string][]uint32
}

const fqnSliceInitCap = 4

func newFqnDimension() fqnDimension {
	return fqnDimension{m: make(map[string][]uint32)}
}

func (d fqnDimension) Add(fqn string, id uint32) {
	ids, ok := d.m[fqn]
	if !ok {
		ids = make([]uint32, 0, fqnSliceInitCap)
	}
	d.m[fqn] = append(ids, id)
}

func (d fqnDimension) Get(fqn string) ([]uint32, bool) {
	ids, ok := d.m[fqn]
	return ids, ok
}

func (d fqnDimension) Delete(fqn string) {
	delete(d.m, fqn)
}
