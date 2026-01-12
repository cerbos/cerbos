// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"github.com/cerbos/cerbos/internal/ruletable/index"
)

type (
	RedisIndex = index.Redis
)

const (
	CategoryKeyVersion      = index.CategoryKeyVersion
	CategoryKeyScope        = index.CategoryKeyScope
	CategoryKeyRoleGlob     = index.CategoryKeyRoleGlob
	CategoryKeyActionGlob   = index.CategoryKeyActionGlob
	CategoryKeyResourceGlob = index.CategoryKeyResourceGlob
)

var (
	ErrCacheMiss = index.ErrCacheMiss

	GetExistingRedis = index.GetExistingRedis
	NewImpl          = index.NewImpl
	NewRedis         = index.NewRedis
)
