// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"github.com/bluele/gcache"
	"github.com/gobwas/glob"
	"go.uber.org/zap"
)

var globs = &globCache{cache: gcache.New(1024).ARC().Build()} //nolint:gomnd

type globCache struct {
	cache gcache.Cache
}

func (gc *globCache) matches(globExpr, val string) bool {
	cachedGlob, err := gc.cache.GetIFPresent(globExpr)
	if err == nil && cachedGlob != nil {
		if g, ok := cachedGlob.(glob.Glob); ok {
			return g.Match(val)
		}
	}

	g, err := glob.Compile(globExpr, ':')
	if err != nil {
		zap.L().Named("glob-cache").Warn("Invalid glob expression", zap.String("glob", globExpr), zap.Error(err))
		return false
	}

	_ = gc.cache.Set(globExpr, g)
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
