// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"math"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"go.uber.org/zap"
)

// dimStats holds size statistics for a single dimension.
type dimStats struct {
	Name     string
	Keys     int
	MinWords int
	MaxWords int
	AvgWords int
	MinCard  uint64
	MaxCard  uint64
	AvgCard  uint64
}

func collectBitmapStats(s *dimStats, bm *Bitmap) {
	wl := bm.WordsLen()
	if wl > s.MaxWords {
		s.MaxWords = wl
	}
	if wl < s.MinWords {
		s.MinWords = wl
	}
	c := bm.GetCardinality()
	if c > s.MaxCard {
		s.MaxCard = c
	}
	if c < s.MinCard {
		s.MinCard = c
	}
}

func dimensionStats[T comparable](name string, d dimension[T]) dimStats {
	s := dimStats{Name: name, Keys: len(d.m), MinWords: math.MaxInt, MinCard: math.MaxUint64}
	totalWords := 0
	totalCard := uint64(0)
	for _, bm := range d.m {
		collectBitmapStats(&s, bm)
		totalWords += bm.WordsLen()
		totalCard += bm.GetCardinality()
	}
	if s.Keys == 0 {
		s.MinWords = 0
		s.MinCard = 0
	} else {
		s.AvgWords = totalWords / s.Keys
		s.AvgCard = totalCard / uint64(s.Keys)
	}
	return s
}

func globDimensionStats(name string, gd *globDimension) dimStats {
	s := dimStats{Name: name, Keys: len(gd.literals) + len(gd.globs), MinWords: math.MaxInt, MinCard: math.MaxUint64}
	totalWords := 0
	totalCard := uint64(0)
	for _, bm := range gd.literals {
		collectBitmapStats(&s, bm)
		totalWords += bm.WordsLen()
		totalCard += bm.GetCardinality()
	}
	for _, bm := range gd.globs {
		collectBitmapStats(&s, bm)
		totalWords += bm.WordsLen()
		totalCard += bm.GetCardinality()
	}
	if s.Keys == 0 {
		s.MinWords = 0
		s.MinCard = 0
	} else {
		s.AvgWords = totalWords / s.Keys
		s.AvgCard = totalCard / uint64(s.Keys)
	}
	return s
}

func (idx *bitmapIndex) logStats(log *zap.SugaredLogger) {
	stats := []dimStats{
		dimensionStats("version", idx.version),
		dimensionStats("scope", idx.scope),
		globDimensionStats("role", idx.role),
		globDimensionStats("resource", idx.resource),
		globDimensionStats("action", idx.action),
		dimensionStats("policyKind", idx.policyKind),
		dimensionStats("principal", idx.principal),
		dimensionStats("fqnBindings", idx.fqnBindings),
	}

	fields := make([]any, 0, 2+len(stats)*8) //nolint:mnd
	fields = append(fields, "bindings", len(idx.bindings), "universe_words", idx.universe.WordsLen())
	for _, s := range stats {
		fields = append(fields,
			s.Name+"_keys", s.Keys,
			s.Name+"_min_words", s.MinWords,
			s.Name+"_avg_words", s.AvgWords,
			s.Name+"_max_words", s.MaxWords,
			s.Name+"_min_card", s.MinCard,
			s.Name+"_avg_card", s.AvgCard,
			s.Name+"_max_card", s.MaxCard,
		)
	}
	log.Debugw("Bitmap index stats", fields...)
}

// bitmapIndex is the core in-memory bitmap index. Each binding gets a uint32 ID,
// and each (dimension, value) pair has a bitmap tracking which binding IDs
// have that value. Queries are flat bitmap AND operations.
type bitmapIndex struct {
	action             *globDimension
	coresBySum         map[uint64]*FunctionalCore // dedup behavioural part
	version            dimension[string]
	scope              dimension[string]
	role               *globDimension
	policyKind         dimension[policyv1.Kind]
	resource           *globDimension
	fqnBindings        dimension[string]
	principal          dimension[string]
	universe           *Bitmap
	allowActionsBitmap *Bitmap
	freeIDs            []uint32
	bindings           []*Binding
}

func newBitmapIndex() *bitmapIndex {
	return &bitmapIndex{
		version:            newDimension[string](),
		scope:              newDimension[string](),
		role:               newGlobDimension(),
		action:             newGlobDimension(),
		resource:           newGlobDimension(),
		policyKind:         newDimension[policyv1.Kind](),
		principal:          newDimension[string](),
		universe:           NewBitmap(),
		allowActionsBitmap: NewBitmap(),
		fqnBindings:        newDimension[string](),
		coresBySum:         make(map[uint64]*FunctionalCore),
	}
}

// allocID returns a uint32 to use as a binding's bit position across all bitmaps.
// It reuses IDs freed by freeID so that repeated add/remove cycles don't grow the
// bindings slice or make the bitmaps increasingly sparse.
func (idx *bitmapIndex) allocID() uint32 {
	if len(idx.freeIDs) > 0 {
		id := idx.freeIDs[len(idx.freeIDs)-1]
		idx.freeIDs = idx.freeIDs[:len(idx.freeIDs)-1]
		return id
	}
	return uint32(len(idx.bindings))
}

func (idx *bitmapIndex) freeID(id uint32) {
	idx.bindings[id] = nil
	idx.freeIDs = append(idx.freeIDs, id)
}

func (idx *bitmapIndex) addBinding(b *Binding) {
	id := idx.allocID()
	b.ID = id
	if int(id) < len(idx.bindings) {
		idx.bindings[id] = b
	} else {
		idx.bindings = append(idx.bindings, b)
	}

	idx.universe.Add(id)

	idx.version.Add(b.Version, id)
	idx.scope.Add(b.Scope, id)

	idx.role.Set(b.Role, id)
	idx.resource.Set(b.Resource, id)

	if b.AllowActions != nil {
		idx.allowActionsBitmap.Add(id)
	} else if b.Action != "" {
		idx.action.Set(b.Action, id)
	}

	idx.policyKind.Add(b.Core.PolicyKind, id)

	if b.Principal != "" {
		idx.principal.Add(b.Principal, id)
	}

	idx.fqnBindings.Add(b.OriginFqn, id)
}

// removeBinding removes the binding from the slice and all dimension bitmaps,
// and returns the ID to the free list.
// It does NOT touch fqnBindings — that is managed by DeletePolicy, which needs
// to inspect fqnBindings across origins before deciding whether to remove the binding.
func (idx *bitmapIndex) removeBinding(b *Binding) {
	id := b.ID

	idx.universe.Remove(id)
	idx.version.Remove(b.Version, id)
	idx.scope.Remove(b.Scope, id)

	idx.role.Remove(b.Role, id)
	idx.resource.Remove(b.Resource, id)

	if b.AllowActions != nil {
		idx.allowActionsBitmap.Remove(id)
	} else if b.Action != "" {
		idx.action.Remove(b.Action, id)
	}

	idx.policyKind.Remove(b.Core.PolicyKind, id)

	if b.Principal != "" {
		idx.principal.Remove(b.Principal, id)
	}

	idx.freeID(id)
}

func (idx *bitmapIndex) getBinding(id uint32) *Binding {
	return idx.bindings[id]
}

// dimension is a thin wrapper around map[T]*Bitmap for exact-match dimensions.
type dimension[T comparable] struct {
	m map[T]*Bitmap
}

func newDimension[T comparable]() dimension[T] {
	return dimension[T]{m: make(map[T]*Bitmap)}
}

func (d dimension[T]) Add(key T, id uint32) {
	bm, ok := d.m[key]
	if !ok {
		bm = NewBitmap()
		d.m[key] = bm
	}
	bm.Add(id)
}

func (d dimension[T]) Remove(key T, id uint32) {
	if bm, ok := d.m[key]; ok {
		bm.Remove(id)
		if bm.IsEmpty() {
			delete(d.m, key)
		}
	}
}

func (d dimension[T]) Get(key T) (*Bitmap, bool) {
	bm, ok := d.m[key]
	return bm, ok
}

func (d dimension[T]) Delete(key T) {
	delete(d.m, key)
}

func (d dimension[T]) Keys() []T {
	keys := make([]T, 0, len(d.m))
	for k := range d.m {
		keys = append(keys, k)
	}
	return keys
}

// Query returns OR(d[k] for k in keys).
// The returned bitmap may alias a stored bitmap; callers must not mutate it.
func (d dimension[T]) Query(arena *bitmapArena, keys []T) *Bitmap {
	parts := make([]*Bitmap, 0, len(keys))
	for _, k := range keys {
		if bm, ok := d.m[k]; ok {
			parts = append(parts, bm)
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
