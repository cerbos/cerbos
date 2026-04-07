// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"

	"github.com/RoaringBitmap/roaring/v2"
)

// bitmapIndex is the core in-memory bitmap index. Each binding gets a uint32 ID,
// and each (dimension, value) pair has a roaring bitmap tracking which binding IDs
// have that value. Queries are flat bitmap AND operations.
type bitmapIndex struct {
	action             *globDimension
	coresBySum         map[uint64]*FunctionalCore // dedup behavioural part
	version            dimension[string]
	scope              dimension[string]
	role               *globDimension
	policyKind         dimension[policyv1.Kind]
	resource           *globDimension
	fqnBindings        dimension[string]
	principal          dimension[string]
	universe           *roaring.Bitmap
	allowActionsBitmap *roaring.Bitmap
	freeIDs            []uint32
	bindings           []*Binding
}

func newBitmapIndex() *bitmapIndex {
	return &bitmapIndex{
		version:            newDimension[string](),
		scope:              newDimension[string](),
		role:               newGlobDimension(),
		action:             newGlobDimension(),
		resource:           newGlobDimension(),
		policyKind:         newDimension[policyv1.Kind](),
		principal:          newDimension[string](),
		universe:           roaring.New(),
		allowActionsBitmap: roaring.New(),
		fqnBindings:        newDimension[string](),
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
	idx.freeIDs = append(idx.freeIDs, id)
}

func (idx *bitmapIndex) addBinding(b *Binding) {
	id := idx.allocID()
	b.ID = id
	if int(id) < len(idx.bindings) {
		idx.bindings[id] = b
	} else {
		idx.bindings = append(idx.bindings, b)
	}

	idx.universe.Add(id)

	idx.version.Add(b.Version, id)
	idx.scope.Add(b.Scope, id)

	idx.role.Set(b.Role, id)
	idx.resource.Set(b.Resource, id)

	if b.AllowActions != nil {
		idx.allowActionsBitmap.Add(id)
	} else if b.Action != "" {
		idx.action.Set(b.Action, id)
	}

	idx.policyKind.Add(b.Core.PolicyKind, id)

	if b.Principal != "" {
		idx.principal.Add(b.Principal, id)
	}

	idx.fqnBindings.Add(b.OriginFqn, id)
}

// removeBinding removes the binding from the slice and all dimension bitmaps,
// and returns the ID to the free list.
// It does NOT touch fqnBindings — that is managed by DeletePolicy, which needs
// to inspect fqnBindings across origins before deciding whether to remove the binding.
func (idx *bitmapIndex) removeBinding(b *Binding) {
	id := b.ID

	idx.universe.Remove(id)
	idx.version.Remove(b.Version, id)
	idx.scope.Remove(b.Scope, id)

	idx.role.Remove(b.Role, id)
	idx.resource.Remove(b.Resource, id)

	if b.AllowActions != nil {
		idx.allowActionsBitmap.Remove(id)
	} else if b.Action != "" {
		idx.action.Remove(b.Action, id)
	}

	idx.policyKind.Remove(b.Core.PolicyKind, id)

	if b.Principal != "" {
		idx.principal.Remove(b.Principal, id)
	}

	idx.freeID(id)
}

func (idx *bitmapIndex) getBinding(id uint32) *Binding {
	return idx.bindings[id]
}

// dimension is a thin wrapper around map[T]*roaring.Bitmap for exact-match dimensions.
type dimension[T comparable] struct {
	m map[T]*roaring.Bitmap
}

func newDimension[T comparable]() dimension[T] {
	return dimension[T]{m: make(map[T]*roaring.Bitmap)}
}

func (d dimension[T]) Add(key T, id uint32) {
	bm, ok := d.m[key]
	if !ok {
		bm = roaring.New()
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

func (d dimension[T]) Get(key T) (*roaring.Bitmap, bool) {
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
func (d dimension[T]) Query(arena *bitmapArena, keys []T) *roaring.Bitmap {
	parts := make([]*roaring.Bitmap, 0, len(keys))
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
