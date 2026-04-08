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

func (idx *bitmapIndex) logStats(log *zap.SugaredLogger) { //nolint:unused
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
