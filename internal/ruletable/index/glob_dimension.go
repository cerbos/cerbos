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
// and glob pattern keys. It mirrors the semantics of internal.GlobMap but
// returns roaring bitmaps instead of rowSets.
type globDimension struct {
	literals   map[string]*roaring.Bitmap
	globs      map[string]*roaring.Bitmap
	compiled   map[string]glob.Glob
	matchCache map[string][]string
}

func newglobDimension() *globDimension {
	return &globDimension{
		literals:   make(map[string]*roaring.Bitmap),
		globs:      make(map[string]*roaring.Bitmap),
		compiled:   make(map[string]glob.Glob),
		matchCache: make(map[string][]string),
	}
}

// Set adds id to the bitmap for the given key, creating it if necessary.
// If key contains a '*', it's treated as a glob pattern.
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
			gd.clearMatchCache()
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

// Remove removes id from the bitmap for the given key. If the bitmap becomes
// empty, the key is deleted.
func (gd *globDimension) Remove(key string, id uint32) {
	if strings.ContainsRune(key, '*') { //nolint:nestif
		if bm, ok := gd.globs[key]; ok {
			bm.Remove(id)
			if bm.IsEmpty() {
				delete(gd.globs, key)
				delete(gd.compiled, key)
				gd.clearMatchCache()
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
func (gd *globDimension) Query(value string) *roaring.Bitmap {
	literalBM := gd.literals[value]
	globs := gd.getMatchingGlobs(value)

	if len(globs) == 0 {
		if literalBM != nil {
			return literalBM
		}
		return roaring.New()
	}

	result := roaring.New()
	if literalBM != nil {
		result.Or(literalBM)
	}
	for _, pattern := range globs {
		if bm, ok := gd.globs[pattern]; ok {
			result.Or(bm)
		}
	}
	return result
}

// QueryMultiple returns OR of all bitmaps matching any of the given values.
// The returned bitmap may alias a stored bitmap; callers must not mutate it.
func (gd *globDimension) QueryMultiple(values []string) *roaring.Bitmap {
	parts := make([]*roaring.Bitmap, 0, len(values))
	for _, v := range values {
		if bm, ok := gd.literals[v]; ok {
			parts = append(parts, bm)
		}
		for _, pattern := range gd.getMatchingGlobs(v) {
			if bm, ok := gd.globs[pattern]; ok {
				parts = append(parts, bm)
			}
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

// GetAllKeys returns all literal and glob keys.
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

func (gd *globDimension) getMatchingGlobs(key string) []string {
	if cached, ok := gd.matchCache[key]; ok {
		return cached
	}

	var matches []string
	for pattern, compiled := range gd.compiled {
		if compiled.Match(key) {
			matches = append(matches, pattern)
		}
	}

	gd.matchCache[key] = matches
	return matches
}

func (gd *globDimension) clearMatchCache() {
	clear(gd.matchCache)
}
