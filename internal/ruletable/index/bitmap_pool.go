// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import "sync"

var bitmapPool = sync.Pool{
	New: func() any {
		b := NewBitmap()
		b.words = make([]uint64, 0, 4) //nolint:mnd
		b.meta = make([]uint64, 0, 1)  //nolint:mnd
		return b
	},
}

// emptyBitmap is shared. Callers must not mutate it.
var emptyBitmap = NewBitmap()

// bitmapArena tracks pooled bitmaps acquired during a single query so they can
// be released in bulk when the query completes.
type bitmapArena struct {
	used []*Bitmap
}

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
// intermediate bitmap allocations. Starts with the largest bitmap so that
// ensure allocates once to the final size.
func (a *bitmapArena) orInto(parts []*Bitmap) *Bitmap {
	maxIdx := 0
	for i := 1; i < len(parts); i++ {
		if parts[i].WordsLen() > parts[maxIdx].WordsLen() {
			maxIdx = i
		}
	}
	bm := a.get()
	bm.Or(parts[maxIdx])
	for i, p := range parts {
		if i != maxIdx {
			bm.Or(p)
		}
	}
	return bm
}

// and2 ANDs exactly two bitmaps into a fresh pooled bitmap. Copies the
// shorter bitmap first to minimise intermediate work.
func (a *bitmapArena) and2(x, y *Bitmap) *Bitmap {
	bm := a.get()
	if x.WordsLen() <= y.WordsLen() {
		bm.Or(x)
		bm.And(y)
	} else {
		bm.Or(y)
		bm.And(x)
	}
	return bm
}

// andInto ANDs bitmaps into a fresh pooled bitmap. Copies the shortest
// bitmap first to minimise intermediate work.
func (a *bitmapArena) andInto(bitmaps []*Bitmap) *Bitmap {
	minIdx := 0
	for i := 1; i < len(bitmaps); i++ {
		if bitmaps[i].WordsLen() < bitmaps[minIdx].WordsLen() {
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
