// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import "slices"

// sparseDimension stores, per key, the sorted binding IDs that have that value,
// instead of a dense Bitmap. For high-cardinality, low-density dimensions (e.g.
// principal) a dense per-value bitmap is almost entirely zeros — its width is set
// by the highest binding ID, not by how many bits are set — so a sorted ID list
// is far smaller. Queries densify the small list into a pooled bitmap on demand
// (see bitmapArena.fromIDs), so the intersection machinery is unchanged.
type sparseDimension struct {
	m map[string][]uint32
}

func newSparseDimension() sparseDimension {
	return sparseDimension{m: make(map[string][]uint32)}
}

// Add inserts id into key's sorted ID list. During a full build allocID hands out
// strictly increasing IDs, so the common case is the append fast path; incremental
// adds after free-list reuse fall back to a sorted insert.
func (d sparseDimension) Add(key string, id uint32) {
	ids := d.m[key]
	if n := len(ids); n == 0 || id > ids[n-1] {
		d.m[key] = append(ids, id)
		return
	}
	i, found := slices.BinarySearch(ids, id)
	if found {
		return
	}
	d.m[key] = slices.Insert(ids, i, id)
}

// Remove deletes id from key's list, dropping the key entirely when it empties
// (matching dimension[T].Remove semantics, which Query relies on for Get's ok).
func (d sparseDimension) Remove(key string, id uint32) {
	ids, ok := d.m[key]
	if !ok {
		return
	}
	i, found := slices.BinarySearch(ids, id)
	if !found {
		return
	}
	ids = slices.Delete(ids, i, i+1)
	if len(ids) == 0 {
		delete(d.m, key)
	} else {
		d.m[key] = ids
	}
}

// Get returns the sorted IDs for key (ascending), if present.
func (d sparseDimension) Get(key string) ([]uint32, bool) {
	ids, ok := d.m[key]
	return ids, ok
}

// compact reallocates each ID list to drop the capacity slack left by append
// doubling. Called once after a full build/reload, mirroring Bitmap.shrinkToFit.
func (d sparseDimension) compact() {
	for k, ids := range d.m {
		if cap(ids) > len(ids) {
			trimmed := make([]uint32, len(ids))
			copy(trimmed, ids)
			d.m[k] = trimmed
		}
	}
}
