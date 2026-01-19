// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"maps"
	"strings"
	"sync"

	"github.com/cerbos/cerbos/internal/cache"
	"github.com/gobwas/glob"
)

const wildcardAny = rune('*')

var globs = &globCache{cache: cache.New[string, glob.Glob]("glob", 1024)} //nolint:mnd

type globCache struct {
	cache *cache.Cache[string, glob.Glob]
}

func (gc *globCache) matches(globExpr, val string) bool {
	g := gc.getOrCompile(globExpr)
	if g == nil {
		return false
	}
	return g.Match(val)
}

func (gc *globCache) getOrCompile(globExpr string) glob.Glob {
	cachedGlob, ok := gc.cache.Get(globExpr)
	if ok {
		return cachedGlob
	}

	g, err := glob.Compile(globExpr, ':')
	if err != nil {
		logError(globExpr, err)
		return nil
	}

	gc.cache.Set(globExpr, g)
	return g
}

// MatchesGlob returns true if the given glob expression matches the given string.
func MatchesGlob(g, val string) bool {
	return globs.matches(fixGlob(g), val)
}

// FilterGlob returns the set of values that match the given glob.
func FilterGlob(g string, values []string) []string {
	globExp := fixGlob(g)
	var out []string

	for _, v := range values {
		if globs.matches(globExp, v) {
			out = append(out, v)
		}
	}

	return out
}

// FilterGlobNotMatches returns the set of values that do not match the given glob.
func FilterGlobNotMatches(g string, values []string) []string {
	globExp := fixGlob(g)
	var out []string

	for _, v := range values {
		if !globs.matches(globExp, v) {
			out = append(out, v)
		}
	}

	return out
}

func fixGlob(g string) string {
	// for backward compatibility, consider single * as **
	if g == "*" {
		return "**"
	}

	return g
}

// GlobMap is a map that supports glob pattern matching for keys.
//
// Thread safety: GlobMap requires external synchronization for write operations
// (Set, Clear, DeleteLiteral). Read operations (Get, GetMerged, GetAll, etc.) may
// run concurrently with each other but not with writes. The internal cacheMu only
// protects matchCache, which can be written during read operations when populating
// the cache on a miss.
type GlobMap[T any] struct {
	literals   map[string]T
	globs      map[string]T
	compiled   map[string]glob.Glob // to avoid sync overhead store local refs to globally compiled globs.
	matchCache map[string][]string  // cache: lookup key -> matching glob patterns
	cacheMu    sync.RWMutex         // protects matchCache
}

func NewGlobMap[T any](m map[string]T) *GlobMap[T] {
	gm := &GlobMap[T]{
		literals:   make(map[string]T),
		globs:      make(map[string]T),
		compiled:   make(map[string]glob.Glob),
		matchCache: make(map[string][]string),
	}

	for k, v := range m {
		gm.Set(k, v)
	}

	return gm
}

func (gm *GlobMap[T]) Len() int {
	return len(gm.literals) + len(gm.globs)
}

// Clear resets the map for reuse, preserving compiled globs to avoid re-fetching from global cache.
func (gm *GlobMap[T]) Clear() {
	clear(gm.literals)
	clear(gm.globs)
	// No lock needed: writes are externally serialized.
	clear(gm.matchCache)
	// Keep gm.compiled - same patterns likely to be reused
}

func (gm *GlobMap[T]) Set(k string, v T) {
	if strings.ContainsRune(k, wildcardAny) {
		if _, exists := gm.globs[k]; !exists {
			g := globs.getOrCompile(fixGlob(k))
			if g == nil {
				return // invalid glob pattern, skip, the error is logged by the callee
			}
			gm.compiled[k] = g
			// No lock needed: writes are externally serialized.
			clear(gm.matchCache)
		}
		gm.globs[k] = v
	} else {
		gm.literals[k] = v
	}
}

func (gm *GlobMap[T]) Get(k string) (T, bool) {
	if v, ok := gm.literals[k]; ok {
		return v, true
	}

	matches := gm.getMatchingGlobs(k)
	if len(matches) > 0 {
		return gm.globs[matches[0]], true
	}

	var zero T
	return zero, false
}

func (gm *GlobMap[T]) GetWithLiteral(k string) (T, bool) {
	if v, ok := gm.literals[k]; ok {
		return v, true
	}

	if v, ok := gm.globs[k]; ok {
		return v, true
	}

	var zero T
	return zero, false
}

func (gm *GlobMap[T]) DeleteLiteral(k string) {
	delete(gm.literals, k)
	if _, hadGlob := gm.globs[k]; hadGlob {
		delete(gm.globs, k)
		delete(gm.compiled, k)
		// No lock needed: writes are externally serialized.
		clear(gm.matchCache)
	}
}

func (gm *GlobMap[T]) GetAll() map[string]T {
	res := make(map[string]T, gm.Len())

	maps.Copy(res, gm.literals)

	maps.Copy(res, gm.globs)

	return res
}

func (gm *GlobMap[T]) GetAllKeys() []string {
	res := make([]string, 0, gm.Len())

	for k := range gm.literals {
		res = append(res, k)
	}

	for k := range gm.globs {
		res = append(res, k)
	}

	return res
}

func (gm *GlobMap[T]) GetMerged(k string) map[string]T {
	// Fast path: no globs, just check literal
	if len(gm.globs) == 0 {
		if v, ok := gm.literals[k]; ok {
			return map[string]T{k: v}
		}
		return make(map[string]T)
	}

	// Slow path
	matches := gm.getMatchingGlobs(k)

	res := make(map[string]T, len(matches)+1)
	if v, ok := gm.literals[k]; ok {
		res[k] = v
	}
	for _, pattern := range matches {
		res[pattern] = gm.globs[pattern]
	}

	return res
}

// getMatchingGlobs returns all glob patterns that match the given key, using cache.
func (gm *GlobMap[T]) getMatchingGlobs(k string) []string {
	gm.cacheMu.RLock()
	if cached, ok := gm.matchCache[k]; ok {
		gm.cacheMu.RUnlock()
		return cached
	}
	gm.cacheMu.RUnlock()

	var matches []string
	for pattern, compiled := range gm.compiled {
		if compiled.Match(k) {
			matches = append(matches, pattern)
		}
	}

	gm.cacheMu.Lock()
	if cached, ok := gm.matchCache[k]; ok {
		gm.cacheMu.Unlock()
		return cached
	}
	gm.matchCache[k] = matches
	gm.cacheMu.Unlock()

	return matches
}
