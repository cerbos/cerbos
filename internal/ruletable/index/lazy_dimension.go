// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"slices"
	"sync/atomic"
)

// lazyDimension stores each value's binding IDs as a sorted slice and materialises
// a dense Bitmap on first query, caching it for later queries — "pay the bitmap
// cost lazily, for the working set only". Building only slices up front makes
// index build/reload cheaper, and values never queried stay as cheap slices.
//
// Concurrency. Queries run under the rule-table RLock (concurrent readers) and are
// the only path that materialises, so each entry's state is an immutable
// lazyState behind an atomic pointer: a query that loses the materialise race
// simply reloads the winner's bitmap. Build and incremental updates run under the
// exclusive Lock (no concurrent queries), so they mutate state in place. The map
// itself is only written under the exclusive Lock.
type lazyDimension struct {
	m map[string]*lazyEntry
}

// lazyState is an immutable snapshot of an entry: cold (ids set, bm nil) until a
// query materialises it to hot (bm set). The ID slice is dropped on
// materialisation, so a hot entry costs no more than the eager bitmap would have.
type lazyState struct {
	bm  *Bitmap
	ids []uint32
}

type lazyEntry struct {
	state atomic.Pointer[lazyState]
}

func newLazyDimension() lazyDimension {
	return lazyDimension{m: make(map[string]*lazyEntry)}
}

// Add appends id to key's IDs (build/incremental only, under the exclusive lock).
// The build path hands out monotonically increasing IDs, so the common case is a
// tail append; incremental adds after free-list reuse fall back to a sorted
// insert. A hot entry's bitmap is updated in place.
func (d lazyDimension) Add(key string, id uint32) {
	e, ok := d.m[key]
	if !ok {
		e = &lazyEntry{}
		e.state.Store(&lazyState{ids: []uint32{id}})
		d.m[key] = e
		return
	}
	st := e.state.Load()
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
	st := e.state.Load()
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
// for concurrent callers (queries hold the rule-table RLock).
func (d lazyDimension) Bitmap(key string) (*Bitmap, bool) {
	e, ok := d.m[key]
	if !ok {
		return nil, false
	}
	st := e.state.Load()
	if st.bm != nil {
		return st.bm, true
	}
	bm := newBitmapFromIDs(st.ids)
	if e.state.CompareAndSwap(st, &lazyState{bm: bm}) {
		return bm, true
	}
	// Lost the race; another query installed its bitmap. Use that one.
	return e.state.Load().bm, true
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

// compact trims the capacity slack left by append growth on cold ID slices (hot
// entries already dropped theirs). Build/reload only.
func (d lazyDimension) compact() {
	for _, e := range d.m {
		st := e.state.Load()
		if st.bm == nil && cap(st.ids) > len(st.ids) {
			trimmed := make([]uint32, len(st.ids))
			copy(trimmed, st.ids)
			st.ids = trimmed
		}
	}
}

// setCold installs key as a cold entry with the given sorted IDs. Used by
// Unmarshal so a reloaded index starts lazy (slices, materialised on demand).
func (d lazyDimension) setCold(key string, ids []uint32) {
	e := &lazyEntry{}
	e.state.Store(&lazyState{ids: ids})
	d.m[key] = e
}

// forEachBitmap yields a bitmap per key for marshalling. Cold entries are
// densified into a transient bitmap that is NOT cached, so marshalling does not
// mutate shared state (it may run concurrently with queries under RLock).
func (d lazyDimension) forEachBitmap(fn func(key string, bm *Bitmap) error) error {
	for k, e := range d.m {
		st := e.state.Load()
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

// intersectingKeys returns the keys whose binding IDs intersect filter. Cold
// entries are probed with filter.Contains rather than materialised, so this scan
// does not force the whole dimension dense.
func (d lazyDimension) intersectingKeys(filter *Bitmap) []string {
	var keys []string
	for k, e := range d.m {
		st := e.state.Load()
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

// newBitmapFromIDs builds a retained dense bitmap with the given sorted IDs set
// (cached by the lazy dimension, not pooled).
func newBitmapFromIDs(ids []uint32) *Bitmap {
	bm := NewBitmap()
	bm.AddSortedBatch(ids)
	return bm
}
