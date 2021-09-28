// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/bluele/gcache"
	"github.com/gobwas/glob"
	"go.uber.org/zap"
)

var globs = &globCache{cache: gcache.New(1024).ARC().Build()}

type globCache struct {
	cache gcache.Cache
}

func (gc *globCache) matches(globExpr, val string) bool {
	cachedGlob, err := gc.cache.GetIFPresent(globExpr)
	if err == nil && cachedGlob != nil {
		g := cachedGlob.(glob.Glob)
		return g.Match(val)
	}

	g, err := glob.Compile(globExpr, ':')
	if err != nil {
		zap.L().Named("glob-cache").Warn("Invalid glob expression", zap.String("glob", globExpr), zap.Error(err))
		return false
	}

	gc.cache.Set(globExpr, g)
	return g.Match(val)
}
