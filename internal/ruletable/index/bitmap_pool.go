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

// newBitmapArena must remain small enough to be inlined so that the arena
// struct is stack-allocated at call sites. Verify with: go build -gcflags='-m'
func newBitmapArena() *bitmapArena {
	return &bitmapArena{used: make([]*Bitmap, 0, 8)} //nolint:mnd
}

func (a *bitmapArena) release() {
	for _, bm := range a.used {
		bm.Clear()
		bitmapPool.Put(bm)
	}
}

// get returns a cleared bitmap from the pool and tracks it for later release.
func (a *bitmapArena) get() *Bitmap {
	bm := bitmapPool.Get().(*Bitmap) //nolint:forcetypeassert
	a.used = append(a.used, bm)
	return bm
}

// orInto ORs all parts into a pooled bitmap using in-place Or, avoiding
// intermediate bitmap allocations.
func (a *bitmapArena) orInto(parts []*Bitmap) *Bitmap {
	bm := a.get()
	for _, p := range parts {
		bm.Or(p)
	}
	return bm
}

// and2 ANDs exactly two bitmaps into a fresh pooled bitmap. Copies the
// smaller bitmap first to minimise intermediate work.
func (a *bitmapArena) and2(x, y *Bitmap) *Bitmap {
	bm := a.get()
	if x.GetCardinality() <= y.GetCardinality() {
		bm.Or(x)
		bm.And(y)
	} else {
		bm.Or(y)
		bm.And(x)
	}
	return bm
}

// andInto ANDs bitmaps into a fresh pooled bitmap. Copies the smallest
// bitmap first to minimise intermediate work.
func (a *bitmapArena) andInto(bitmaps []*Bitmap) *Bitmap {
	minIdx := 0
	minCard := bitmaps[0].GetCardinality()
	for i := 1; i < len(bitmaps); i++ {
		if c := bitmaps[i].GetCardinality(); c < minCard {
			minCard = c
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
