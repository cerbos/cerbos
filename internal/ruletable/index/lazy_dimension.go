// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"slices"
	"sync/atomic"
)

// lazyDimension stores each value's binding IDs as a sorted slice, unless
// bitmap is smaller, and materialises a Bitmap on first query, caching it
// for later queries — "pay the bitmap cost lazily, for the working set only".
//
// Concurrency. Queries run under the rule-table RLock (concurrent readers) and are
// the only path that materialises, so each key maps to an atomic pointer to an
// immutable lazyState: a query that loses the materialise race simply reloads the
// winner's bitmap. Build and incremental updates run under the exclusive Lock (no
// concurrent queries), so they mutate state in place. The map itself is only
// written under the exclusive Lock.
type lazyDimension struct {
	m map[string]*atomic.Pointer[lazyState]
}

// lazyState is an immutable snapshot of an entry: cold (ids set, bm nil)
// until a query materialises it to hot (bm set). The ID slice is dropped on
// materialisation.
type lazyState struct {
	bm  *Bitmap
	ids []uint32
}

func newLazyDimension() lazyDimension {
	return lazyDimension{m: make(map[string]*atomic.Pointer[lazyState])}
}

// Add appends id to key's IDs (build/incremental only, under the exclusive lock).
func (d lazyDimension) Add(key string, id uint32) {
	e, ok := d.m[key]
	if !ok {
		e = new(atomic.Pointer[lazyState])
		e.Store(&lazyState{ids: []uint32{id}})
		d.m[key] = e
		return
	}
	st := e.Load()
	if st.bm != nil {
		st.bm.Add(id)
		return
	}
	st.ids = insertSortedUnique(st.ids, id)
}

// Remove deletes id from key, dropping the key when it empties (Bitmap relies on a
// missing key meaning "no match"). Incremental only, under the exclusive lock.
func (d lazyDimension) Remove(key string, id uint32) {
	e, ok := d.m[key]
	if !ok {
		return
	}
	st := e.Load()
	if st.bm != nil {
		st.bm.Remove(id)
		if st.bm.IsEmpty() {
			delete(d.m, key)
		}
		return
	}
	i, found := slices.BinarySearch(st.ids, id)
	if !found {
		return
	}
	st.ids = slices.Delete(st.ids, i, i+1)
	if len(st.ids) == 0 {
		delete(d.m, key)
	}
}

// Bitmap returns key's bitmap, materialising and caching it on first call. Safe
// for concurrent callers (assumes queries hold the rule-table RLock).
func (d lazyDimension) Bitmap(key string) (*Bitmap, bool) {
	e, ok := d.m[key]
	if !ok {
		return nil, false
	}
	st := e.Load()
	if st.bm != nil {
		return st.bm, true
	}
	bm := newBitmapFromIDs(st.ids)
	if e.CompareAndSwap(st, &lazyState{bm: bm}) {
		return bm, true
	}
	// Lost the race; another query installed its bitmap. Use that one.
	return e.Load().bm, true
}

// Keys returns the dimension's keys (order unspecified).
func (d lazyDimension) Keys() []string {
	keys := make([]string, 0, len(d.m))
	for k := range d.m {
		keys = append(keys, k)
	}
	return keys
}

func (d lazyDimension) len() int { return len(d.m) }

// has reports whether key is present (without materialising it).
func (d lazyDimension) has(key string) bool {
	_, ok := d.m[key]
	return ok
}

// compact finalises every cold entry built so far, picking the smaller backing
// store for each.
func (d lazyDimension) compact() {
	const (
		bitsPerWord  = 64 // bits in a data word
		wordsPerMeta = 64 // data words tracked per meta word
	)
	for _, e := range d.m {
		st := e.Load()
		if st.bm != nil || len(st.ids) == 0 {
			continue
		}
		words := int(st.ids[len(st.ids)-1]/bitsPerWord) + 1
		metaWords := (words + wordsPerMeta - 1) / wordsPerMeta // ⌈words / wordsPerMeta⌉
		if preferBitmap(words, metaWords, len(st.ids)) {
			e.Store(&lazyState{bm: newBitmapFromIDs(st.ids)})
			continue
		}
		if cap(st.ids) > len(st.ids) {
			trimmed := make([]uint32, len(st.ids))
			copy(trimmed, st.ids)
			st.ids = trimmed
		}
	}
}

// preferBitmap reports whether a dense bitmap of the given word/meta counts is no
// larger than a sorted []uint32 holding the same cardinality IDs.
func preferBitmap(words, metaWords, cardinality int) bool {
	const uint32Bytes = 4
	return (words+metaWords)*wordSize <= cardinality*uint32Bytes
}

// setFromBitmap installs key from a freshly decoded bitmap, keeping that bitmap
// when it is the smaller representation (dense) and otherwise extracting a cold
// sorted ID slice (sparse).
func (d lazyDimension) setFromBitmap(key string, bm *Bitmap) {
	e := new(atomic.Pointer[lazyState])
	card := int(bm.GetCardinality())
	if preferBitmap(len(bm.words), len(bm.meta), card) {
		e.Store(&lazyState{bm: bm})
	} else {
		ids := make([]uint32, 0, card)
		for it := bm.Iterator(); it.HasNext(); {
			ids = append(ids, it.Next())
		}
		e.Store(&lazyState{ids: ids})
	}
	d.m[key] = e
}

// forEachBitmap yields a bitmap per key for marshalling. Cold entries are
// densified into a transient bitmap that is NOT cached, so safe to run concurrently.
func (d lazyDimension) forEachBitmap(fn func(key string, bm *Bitmap) error) error {
	for k, e := range d.m {
		st := e.Load()
		bm := st.bm
		if bm == nil {
			bm = newBitmapFromIDs(st.ids)
		}
		if err := fn(k, bm); err != nil {
			return err
		}
	}
	return nil
}

// intersectingKeys returns the keys whose binding IDs intersect filter.
func (d lazyDimension) intersectingKeys(filter *Bitmap) []string {
	var keys []string
	for k, e := range d.m {
		st := e.Load()
		if st.bm != nil {
			if intersectionNonEmpty(st.bm, filter) {
				keys = append(keys, k)
			}
			continue
		}
		if slices.ContainsFunc(st.ids, filter.Contains) {
			keys = append(keys, k)
		}
	}
	return keys
}

// insertSortedUnique inserts id into the sorted slice, returning it unchanged if
// id is already present.
func insertSortedUnique(ids []uint32, id uint32) []uint32 {
	if n := len(ids); n == 0 || id > ids[n-1] {
		return append(ids, id)
	}
	i, found := slices.BinarySearch(ids, id)
	if found {
		return ids
	}
	return slices.Insert(ids, i, id)
}

// newBitmapFromIDs builds a retained dense bitmap with the given sorted IDs set.
func newBitmapFromIDs(ids []uint32) *Bitmap {
	bm := NewBitmap()
	bm.AddSortedBatch(ids)
	return bm
}
