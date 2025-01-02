// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"

	"github.com/doug-martin/goqu/v9"

	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/util"
)

// DBOpt defines database driver options.
type DBOpt func(*dbOpt)

type (
	upsertPolicyFunc func(ctx context.Context, tx *goqu.TxDatabase, p policy.Wrapper) error
	upsertSchemaFunc func(ctx context.Context, tx *goqu.TxDatabase, schema Schema) error
)

type dbOpt struct {
	upsertPolicy     upsertPolicyFunc
	upsertSchema     upsertSchemaFunc
	regexpCache      *util.RegexpCache
	sourceAttributes []policy.SourceAttribute
}

func newDbOpt() *dbOpt {
	return &dbOpt{
		regexpCache: util.NewRegexpCache(),
	}
}

// WithUpsertSchema sets custom upsert schema function.
func WithUpsertSchema(f upsertSchemaFunc) DBOpt {
	return func(opt *dbOpt) {
		opt.upsertSchema = f
	}
}

// WithUpsertPolicy sets custom upsert policy function.
func WithUpsertPolicy(f upsertPolicyFunc) DBOpt {
	return func(opt *dbOpt) {
		opt.upsertPolicy = f
	}
}

// WithRegexpCacheOverride overrides the default regexp cache for DB queries requiring compiled expressions.
// This is only required for DB drivers that require access to the cache (e.g. The SQLite driver retrieves the compiled
// expressions for the application-defined function).
func WithRegexpCacheOverride(c *util.RegexpCache) DBOpt {
	return func(opt *dbOpt) {
		opt.regexpCache = c
	}
}

// WithSourceAttributes sets the policy source attributes.
func WithSourceAttributes(attr ...policy.SourceAttribute) DBOpt {
	return func(opt *dbOpt) {
		opt.sourceAttributes = attr
	}
}
