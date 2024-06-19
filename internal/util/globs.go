// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"strings"

	"github.com/cerbos/cerbos/internal/cache"
	"github.com/gobwas/glob"
	"go.uber.org/zap"
)

const wildcardAny = rune('*')

var globs = &globCache{cache: cache.New[string, glob.Glob]("glob", 1024)} //nolint:mnd

type globCache struct {
	cache *cache.Cache[string, glob.Glob]
}

func (gc *globCache) matches(globExpr, val string) bool {
	cachedGlob, ok := gc.cache.Get(globExpr)
	if ok {
		return cachedGlob.Match(val)
	}

	g, err := glob.Compile(globExpr, ':')
	if err != nil {
		zap.L().Named("glob-cache").Warn("Invalid glob expression", zap.String("glob", globExpr), zap.Error(err))
		return false
	}

	gc.cache.Set(globExpr, g)
	return g.Match(val)
}

// MatchesGlob returns true if the given glob expression matches the given string.
func MatchesGlob(globExpr, val string) bool {
	return globs.matches(globExpr, val)
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

type GlobMap[T any] struct {
	literals map[string]T
	globs    map[string]T
}

func NewGlobMap[T any](m map[string]T) *GlobMap[T] {
	gm := &GlobMap[T]{
		literals: make(map[string]T),
		globs:    make(map[string]T),
	}

	for k, v := range m {
		if strings.ContainsRune(k, wildcardAny) {
			gm.globs[k] = v
		} else {
			gm.literals[k] = v
		}
	}

	return gm
}

func (gm *GlobMap[T]) Get(k string) T {
	if v, ok := gm.literals[k]; ok {
		return v
	}

	for g, v := range gm.globs {
		if MatchesGlob(g, k) {
			return v
		}
	}

	var zero T
	return zero
}
