// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"sync"

	"github.com/RoaringBitmap/roaring/v2"
)

var bitmapPool = sync.Pool{
	New: func() any { return roaring.New() },
}

// emptyBitmap is shared. Callers must not mutate it.
var emptyBitmap = roaring.New()

// bitmapArena tracks pooled bitmaps acquired during a single query so they can
// be released in bulk when the query completes.
type bitmapArena struct {
	used []*roaring.Bitmap
}

func newBitmapArena() *bitmapArena {
	return &bitmapArena{used: make([]*roaring.Bitmap, 0, 8)} //nolint:mnd
}

func (a *bitmapArena) release() {
	for _, bm := range a.used {
		bm.Clear()
		bitmapPool.Put(bm)
	}
}

// get returns a cleared bitmap from the pool and tracks it for later release.
func (a *bitmapArena) get() *roaring.Bitmap {
	bm := bitmapPool.Get().(*roaring.Bitmap) //nolint:forcetypeassert
	a.used = append(a.used, bm)
	return bm
}

// orInto ORs all parts into a pooled bitmap using in-place Or. This avoids
// roaring.FastOr's lazy-OR path, which allocates N-1 intermediate array
// containers that become immediate GC pressure. In-place Or merges directly
// into the destination's containers, which grow once and are reused.
func (a *bitmapArena) orInto(parts []*roaring.Bitmap) *roaring.Bitmap {
	bm := a.get()
	for _, p := range parts {
		bm.Or(p)
	}
	return bm
}

// and2 ANDs exactly two bitmaps into a fresh pooled bitmap, avoiding a
// heap-allocated slice.
func (a *bitmapArena) and2(x, y *roaring.Bitmap) *roaring.Bitmap {
	if x.IsEmpty() || y.IsEmpty() {
		return emptyBitmap
	}
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

// andInto ANDs bitmaps into a fresh pooled bitmap. The smallest bitmap is
// copied first to minimise intermediate work.
func (a *bitmapArena) andInto(bitmaps []*roaring.Bitmap) *roaring.Bitmap {
	minIdx := 0
	minCard := bitmaps[0].GetCardinality()
	for i := 1; i < len(bitmaps); i++ {
		if c := bitmaps[i].GetCardinality(); c < minCard {
			minCard = c
			minIdx = i
		}
	}
	if minCard == 0 {
		return emptyBitmap
	}
	bm := a.get()
	bm.Or(bitmaps[minIdx]) // copy smallest
	for i, other := range bitmaps {
		if i != minIdx {
			bm.And(other)
		}
	}
	return bm
}
