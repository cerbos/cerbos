// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"regexp"
	"sync"

	"github.com/doug-martin/goqu/v9"

	"github.com/cerbos/cerbos/internal/policy"
)

// DBOpt defines database driver options.
type DBOpt func(*dbOpt)

type (
	upsertPolicyFunc func(ctx context.Context, tx *goqu.TxDatabase, p policy.Wrapper) error
	upsertSchemaFunc func(ctx context.Context, tx *goqu.TxDatabase, schema Schema) error
)

type RegexpCache struct {
	c  map[string]*regexp.Regexp
	mu *sync.Mutex
}

func NewRegexpCache() *RegexpCache {
	return &RegexpCache{
		c:  make(map[string]*regexp.Regexp),
		mu: &sync.Mutex{},
	}
}

// GetCompiledExpr lazily compiles (and stores) regexp.
func (c *RegexpCache) GetCompiledExpr(re string) (*regexp.Regexp, error) {
	// TODO(saml) how to protect against this nil scenario?
	if c == nil {
		return nil, nil
	}

	// TODO(saml) RWLock??
	c.mu.Lock()
	defer c.mu.Unlock()

	r, ok := c.c[re]
	if !ok {
		var err error
		if r, err = regexp.Compile(re); err != nil {
			return nil, err
		}
		c.c[re] = r
	}

	return r, nil
}

type dbOpt struct {
	upsertPolicy upsertPolicyFunc
	upsertSchema upsertSchemaFunc
	regexpCache  *RegexpCache
}

func newDbOpt() *dbOpt {
	return &dbOpt{
		regexpCache: NewRegexpCache(),
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

// WithRegexpCacheOverride overrides the default regexp cache forto DB queries requiring compiled expressions.
// This is only required for DB drivers that require access to the cache (e.g. The SQLite driver retrieves the compiled
// expressions for the application-defined function).
func WithRegexpCacheOverride(c *RegexpCache) DBOpt {
	return func(opt *dbOpt) {
		opt.regexpCache = c
	}
}
