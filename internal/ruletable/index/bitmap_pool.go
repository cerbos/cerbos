// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import "sync"

var bitmapPool = sync.Pool{
	New: func() any { return NewBitmap() },
}

// emptyBitmap is shared. Callers must not mutate it.
var emptyBitmap = NewBitmap()

// bitmapArena tracks pooled bitmaps acquired during a single query so they can
// be released in bulk when the query completes.
type bitmapArena struct {
	used []*Bitmap
}

var arenaPool = sync.Pool{
	New: func() any { return &bitmapArena{used: make([]*Bitmap, 0, 8)} }, //nolint:mnd
}

func acquireArena() *bitmapArena {
	return arenaPool.Get().(*bitmapArena) //nolint:forcetypeassert
}

func (a *bitmapArena) release() {
	for _, bm := range a.used {
		bm.Clear()
		bitmapPool.Put(bm)
	}
	a.used = a.used[:0]
	arenaPool.Put(a)
}

// get returns a cleared bitmap from the pool and tracks it for later release.
func (a *bitmapArena) get() *Bitmap {
	bm := bitmapPool.Get().(*Bitmap) //nolint:forcetypeassert
	a.used = append(a.used, bm)
	return bm
}

// orInto ORs all parts into a pooled bitmap using in-place Or. This avoids
// roaring.FastOr's lazy-OR path, which allocates N-1 intermediate array
// containers that become immediate GC pressure. In-place Or merges directly
// into the destination's containers, which grow once and are reused.
func (a *bitmapArena) orInto(parts []*Bitmap) *Bitmap {
	bm := a.get()
	for _, p := range parts {
		bm.Or(p)
	}
	return bm
}

// and2 ANDs exactly two bitmaps into a fresh pooled bitmap. Copies the
// shorter bitmap (by Len, the highest set bit) first to minimise work.
func (a *bitmapArena) and2(x, y *Bitmap) *Bitmap {
	bm := a.get()
	if x.Len() <= y.Len() {
		bm.Or(x)
		bm.And(y)
	} else {
		bm.Or(y)
		bm.And(x)
	}
	return bm
}

// andInto ANDs bitmaps into a fresh pooled bitmap. Copies the shortest
// bitmap (by Len) first to minimise intermediate work.
func (a *bitmapArena) andInto(bitmaps []*Bitmap) *Bitmap {
	minIdx := 0
	minLen := bitmaps[0].Len()
	for i := 1; i < len(bitmaps); i++ {
		if l := bitmaps[i].Len(); l < minLen {
			minLen = l
			minIdx = i
		}
	}
	bm := a.get()
	bm.Or(bitmaps[minIdx])
	for i, other := range bitmaps {
		if i != minIdx {
			bm.And(other)
		}
	}
	return bm
}
