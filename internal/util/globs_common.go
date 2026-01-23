// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"github.com/cerbos/cerbos/internal/cache"
	"github.com/gobwas/glob"
)

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

// GetOrCompileGlob returns a compiled glob for the given expression, using the global cache.
// Returns nil if the glob expression is invalid.
func GetOrCompileGlob(globExpr string) glob.Glob {
	return globs.getOrCompile(fixGlob(globExpr))
}
