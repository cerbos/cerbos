// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"strings"

	"github.com/cerbos/cerbos/internal/util"
	"github.com/gobwas/glob"
)

// globDimension is a bitmap-based dimension index that supports both literal
// and glob pattern keys. It mirrors the semantics of internal.GlobMap,
// returning bitmaps for queried values.
type globDimension struct {
	// literals is stored lazily (sorted IDs per value, materialised to a bitmap on
	// first query) — it's the high-cardinality part (e.g. one key per resource).
	literals lazyDimension
	// `globs` and `compiled` share the same key. Globs are few, so kept dense.
	globs    map[string]*Bitmap
	compiled map[string]glob.Glob
}

func newGlobDimension() *globDimension {
	return &globDimension{
		literals: newLazyDimension(),
		globs:    make(map[string]*Bitmap),
		compiled: make(map[string]glob.Glob),
	}
}

func (gd *globDimension) Set(key string, id uint32) {
	if strings.ContainsRune(key, '*') { //nolint:nestif
		bm, ok := gd.globs[key]
		if !ok {
			g := util.GetOrCompileGlob(key)
			if g == nil {
				return
			}
			gd.compiled[key] = g
			bm = NewBitmap()
			gd.globs[key] = bm
		}
		bm.Add(id)
	} else {
		gd.literals.Add(key, id)
	}
}

func (gd *globDimension) Remove(key string, id uint32) {
	if strings.ContainsRune(key, '*') { //nolint:nestif
		if bm, ok := gd.globs[key]; ok {
			bm.Remove(id)
			if bm.IsEmpty() {
				delete(gd.globs, key)
				delete(gd.compiled, key)
			}
		}
	} else {
		gd.literals.Remove(key, id)
	}
}

// Query returns the OR of the literal bitmap for value and all glob bitmaps
// whose pattern matches value. The returned bitmap may alias a stored bitmap;
// callers must not mutate it.
func (gd *globDimension) Query(arena *bitmapArena, value string) *Bitmap {
	literalBM, _ := gd.literals.Bitmap(value) // nil if absent; materialises on first use

	if len(gd.compiled) == 0 {
		if literalBM != nil {
			return literalBM
		}
		return emptyBitmap
	}

	// Collect literal + matching glob bitmaps and combine with in-place OR.
	var parts []*Bitmap
	if literalBM != nil {
		parts = append(parts, literalBM)
	}
	for pattern, compiled := range gd.compiled {
		if compiled.Match(value) {
			parts = append(parts, gd.globs[pattern])
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

// QueryMultiple returns OR of all bitmaps matching any of the given values.
// The returned bitmap may alias a stored bitmap; callers must not mutate it.
func (gd *globDimension) QueryMultiple(arena *bitmapArena, values []string) *Bitmap {
	parts := make([]*Bitmap, 0, len(values))
	for _, v := range values {
		if bm, ok := gd.literals.Bitmap(v); ok {
			parts = append(parts, bm)
		}
		for pattern, compiled := range gd.compiled {
			if compiled.Match(v) {
				parts = append(parts, gd.globs[pattern])
			}
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

func (gd *globDimension) GetAllKeys() []string {
	keys := make([]string, 0, gd.literals.len()+len(gd.globs))
	keys = append(keys, gd.literals.Keys()...)
	for k := range gd.globs {
		keys = append(keys, k)
	}
	return keys
}

// intersectingKeys returns the keys (literal values and glob patterns) whose
// binding IDs intersect filter. Cold literals are probed via filter.Contains so
// the lazy literals are not materialised by this scan.
func (gd *globDimension) intersectingKeys(filter *Bitmap) []string {
	keys := gd.literals.intersectingKeys(filter)
	for pattern, bm := range gd.globs {
		if intersectionNonEmpty(bm, filter) {
			keys = append(keys, pattern)
		}
	}
	return keys
}

// compact trims the lazy literals' slice slack and shrinks the (dense) glob
// bitmaps. Build/reload only.
func (gd *globDimension) compact() {
	gd.literals.compact()
	for _, bm := range gd.globs {
		bm.shrinkToFit()
	}
}
