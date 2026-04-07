// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"strings"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/gobwas/glob"
)

// globDimension is a bitmap-based dimension index that supports both literal
// and glob pattern keys. It mirrors the semantics of internal.GlobMap,
// returning roaring bitmaps for queried values.
type globDimension struct {
	// Raw maps rather than dimension[string] because globs and compiled have
	// coupled lifecycles that don't fit the dimension abstraction cleanly.
	literals map[string]*roaring.Bitmap
	// `globs` and `compiled` share the same key
	globs    map[string]*roaring.Bitmap
	compiled map[string]glob.Glob
}

func newGlobDimension() *globDimension {
	return &globDimension{
		literals: make(map[string]*roaring.Bitmap),
		globs:    make(map[string]*roaring.Bitmap),
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
			bm = roaring.New()
			gd.globs[key] = bm
		}
		bm.Add(id)
	} else {
		bm, ok := gd.literals[key]
		if !ok {
			bm = roaring.New()
			gd.literals[key] = bm
		}
		bm.Add(id)
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
		if bm, ok := gd.literals[key]; ok {
			bm.Remove(id)
			if bm.IsEmpty() {
				delete(gd.literals, key)
			}
		}
	}
}

// Query returns the OR of the literal bitmap for value and all glob bitmaps
// whose pattern matches value. The returned bitmap may alias a stored bitmap;
// callers must not mutate it.
func (gd *globDimension) Query(arena *bitmapArena, value string) *roaring.Bitmap {
	literalBM := gd.literals[value]

	if len(gd.compiled) == 0 {
		if literalBM != nil {
			return literalBM
		}
		return emptyBitmap
	}

	// Collect literal + matching glob bitmaps and combine with in-place OR.
	var parts []*roaring.Bitmap
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
func (gd *globDimension) QueryMultiple(arena *bitmapArena, values []string) *roaring.Bitmap {
	parts := make([]*roaring.Bitmap, 0, len(values))
	for _, v := range values {
		if bm, ok := gd.literals[v]; ok {
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
	keys := make([]string, 0, len(gd.literals)+len(gd.globs))
	for k := range gd.literals {
		keys = append(keys, k)
	}
	for k := range gd.globs {
		keys = append(keys, k)
	}
	return keys
}
