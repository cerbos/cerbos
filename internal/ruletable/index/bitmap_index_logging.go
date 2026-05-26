// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package index

import (
	"math"

	"go.uber.org/zap"
)

// dimStats holds size statistics for a single dimension.
type dimStats struct { //nolint:unused
	Name     string
	Keys     int
	MinWords int
	MaxWords int
	AvgWords int
	MinCard  uint64
	MaxCard  uint64
	AvgCard  uint64
}

func collectBitmapStats(s *dimStats, bm *Bitmap) { //nolint:unused
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

func dimensionStats[T comparable](name string, d dimension[T]) dimStats { //nolint:unused
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

func globDimensionStats(name string, gd *globDimension) dimStats { //nolint:unused
	s := dimStats{Name: name, Keys: gd.literals.len() + len(gd.globs), MinWords: math.MaxInt, MinCard: math.MaxUint64}
	totalWords := 0
	totalCard := uint64(0)
	for _, e := range gd.literals.m {
		st := e.Load()
		var c uint64
		wl := 0
		if st.bm != nil {
			c = st.bm.GetCardinality()
			wl = st.bm.WordsLen()
		} else {
			c = uint64(len(st.ids))
			if n := len(st.ids); n > 0 {
				wl = int(st.ids[n-1]/64) + 1 //nolint:mnd
			}
		}
		if wl > s.MaxWords {
			s.MaxWords = wl
		}
		if wl < s.MinWords {
			s.MinWords = wl
		}
		if c > s.MaxCard {
			s.MaxCard = c
		}
		if c < s.MinCard {
			s.MinCard = c
		}
		totalWords += wl
		totalCard += c
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

func fqnDimensionStats(name string, d fqnDimension) dimStats { //nolint:unused
	s := dimStats{Name: name, Keys: len(d.m), MinWords: math.MaxInt, MinCard: math.MaxUint64}
	totalCard := uint64(0)
	for _, ids := range d.m {
		c := uint64(len(ids))
		if c > s.MaxCard {
			s.MaxCard = c
		}
		if c < s.MinCard {
			s.MinCard = c
		}
		totalCard += c
	}
	if s.Keys == 0 {
		s.MinWords = 0
		s.MinCard = 0
	} else {
		s.AvgCard = totalCard / uint64(s.Keys)
	}
	return s
}

// lazyDimensionStats mirrors dimensionStats for a lazyDimension without
// materialising cold entries. Card is the number of IDs per key; Words is the
// actual word count for hot (materialised) entries, or the dense-equivalent
// (highest ID / 64) for cold ones.
func lazyDimensionStats(name string, d lazyDimension) dimStats { //nolint:unused
	s := dimStats{Name: name, Keys: d.len(), MinWords: math.MaxInt, MinCard: math.MaxUint64}
	totalWords := 0
	totalCard := uint64(0)
	for _, e := range d.m {
		st := e.Load()
		var c uint64
		wl := 0
		if st.bm != nil {
			c = st.bm.GetCardinality()
			wl = st.bm.WordsLen()
		} else {
			c = uint64(len(st.ids))
			if n := len(st.ids); n > 0 {
				wl = int(st.ids[n-1]/64) + 1 //nolint:mnd
			}
		}
		if wl > s.MaxWords {
			s.MaxWords = wl
		}
		if wl < s.MinWords {
			s.MinWords = wl
		}
		if c > s.MaxCard {
			s.MaxCard = c
		}
		if c < s.MinCard {
			s.MinCard = c
		}
		totalWords += wl
		totalCard += c
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

func (idx *bitmapIndex) logStats(log *zap.SugaredLogger) { //nolint:unused
	stats := []dimStats{
		dimensionStats("version", idx.version),
		dimensionStats("scope", idx.scope),
		globDimensionStats("role", idx.role),
		globDimensionStats("resource", idx.resource),
		globDimensionStats("action", idx.action),
		dimensionStats("policyKind", idx.policyKind),
		lazyDimensionStats("principal", idx.principal),
		fqnDimensionStats("fqnBindings", idx.fqnBindings),
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
