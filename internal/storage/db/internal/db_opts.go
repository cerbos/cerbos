// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"

	"github.com/doug-martin/goqu/v9"

	"github.com/cerbos/cerbos/internal/policy"
)

// DBOpt defines database driver options.
type DBOpt func(*dbOpt)

type (
	upsertPolicyFunc func(ctx context.Context, tx *goqu.TxDatabase, p policy.Wrapper) error
	upsertSchemaFunc func(ctx context.Context, tx *goqu.TxDatabase, schema Schema) error
)

type dbOpt struct {
	upsertPolicy upsertPolicyFunc
	upsertSchema upsertSchemaFunc
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
