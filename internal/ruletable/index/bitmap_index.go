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
	coresBySum         map[uint64]*FunctionalCore
	bindingDedup       map[uint64]uint32
	version            map[string]*roaring.Bitmap
	scope              map[string]*roaring.Bitmap
	role               *globDimension
	policyKind         map[policyv1.Kind]*roaring.Bitmap
	resource           *globDimension
	fqnBindings        map[string]*roaring.Bitmap
	principal          map[string]*roaring.Bitmap
	universe           *roaring.Bitmap
	allowActionsBitmap *roaring.Bitmap
	freeIDs            []uint32
	bindings           []*Binding
	nextID             uint32
}

func newBitmapIndex() *bitmapIndex {
	return &bitmapIndex{
		version:            make(map[string]*roaring.Bitmap),
		scope:              make(map[string]*roaring.Bitmap),
		role:               newGlobDimension(),
		action:             newGlobDimension(),
		resource:           newGlobDimension(),
		policyKind:         make(map[policyv1.Kind]*roaring.Bitmap),
		principal:          make(map[string]*roaring.Bitmap),
		universe:           roaring.New(),
		allowActionsBitmap: roaring.New(),
		fqnBindings:        make(map[string]*roaring.Bitmap),
		coresBySum:         make(map[uint64]*FunctionalCore),
		bindingDedup:       make(map[uint64]uint32),
	}
}

func (bi *bitmapIndex) allocID() uint32 {
	if len(bi.freeIDs) > 0 {
		id := bi.freeIDs[len(bi.freeIDs)-1]
		bi.freeIDs = bi.freeIDs[:len(bi.freeIDs)-1]
		return id
	}
	id := bi.nextID
	bi.nextID++
	return id
}

func (bi *bitmapIndex) freeID(id uint32) {
	if int(id) < len(bi.bindings) {
		bi.bindings[id] = nil
	}
	bi.freeIDs = append(bi.freeIDs, id)
}

func (bi *bitmapIndex) storeBinding(b *Binding) {
	id := b.ID
	if int(id) >= len(bi.bindings) {
		bi.bindings = append(bi.bindings, make([]*Binding, int(id)-len(bi.bindings)+1)...)
	}
	bi.bindings[id] = b
}

func (bi *bitmapIndex) addToDimensions(b *Binding) {
	id := b.ID

	bi.universe.Add(id)
	addToLiteralMap(bi.version, b.Version, id)
	addToLiteralMap(bi.scope, b.Scope, id)

	bi.role.Set(b.Role, id)
	bi.resource.Set(b.Resource, id)

	if b.AllowActions != nil {
		bi.allowActionsBitmap.Add(id)
	} else if b.Action != "" {
		bi.action.Set(b.Action, id)
	}

	addToKindMap(bi.policyKind, b.Core.PolicyKind, id)

	if b.Principal != "" {
		addToLiteralMap(bi.principal, b.Principal, id)
	}

	addToLiteralMap(bi.fqnBindings, b.OriginFqn, id)
}

func (bi *bitmapIndex) removeFromDimensions(b *Binding) {
	id := b.ID

	bi.universe.Remove(id)
	removeFromLiteralMap(bi.version, b.Version, id)
	removeFromLiteralMap(bi.scope, b.Scope, id)

	bi.role.Remove(b.Role, id)
	bi.resource.Remove(b.Resource, id)

	if b.AllowActions != nil {
		bi.allowActionsBitmap.Remove(id)
	} else if b.Action != "" {
		bi.action.Remove(b.Action, id)
	}

	removeFromKindMap(bi.policyKind, b.Core.PolicyKind, id)

	if b.Principal != "" {
		removeFromLiteralMap(bi.principal, b.Principal, id)
	}
}

func (bi *bitmapIndex) getBinding(id uint32) *Binding {
	if int(id) >= len(bi.bindings) {
		return nil
	}
	return bi.bindings[id]
}

func addToLiteralMap(m map[string]*roaring.Bitmap, key string, id uint32) {
	bm, ok := m[key]
	if !ok {
		bm = roaring.New()
		m[key] = bm
	}
	bm.Add(id)
}

func removeFromLiteralMap(m map[string]*roaring.Bitmap, key string, id uint32) {
	if bm, ok := m[key]; ok {
		bm.Remove(id)
		if bm.IsEmpty() {
			delete(m, key)
		}
	}
}

func addToKindMap(m map[policyv1.Kind]*roaring.Bitmap, kind policyv1.Kind, id uint32) {
	bm, ok := m[kind]
	if !ok {
		bm = roaring.New()
		m[kind] = bm
	}
	bm.Add(id)
}

func removeFromKindMap(m map[policyv1.Kind]*roaring.Bitmap, kind policyv1.Kind, id uint32) {
	if bm, ok := m[kind]; ok {
		bm.Remove(id)
		if bm.IsEmpty() {
			delete(m, kind)
		}
	}
}

// queryLiteralMap returns OR(m[k] for k in keys). Keys must not be empty.
// The returned bitmap may alias a stored bitmap; callers must not mutate it.
func queryLiteralMap(m map[string]*roaring.Bitmap, keys []string) *roaring.Bitmap {
	parts := make([]*roaring.Bitmap, 0, len(keys))
	for _, k := range keys {
		if bm, ok := m[k]; ok {
			parts = append(parts, bm)
		}
	}
	switch len(parts) {
	case 0:
		return roaring.New()
	case 1:
		return parts[0]
	default:
		return roaring.FastOr(parts...)
	}
}
