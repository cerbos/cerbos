// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package overlay_test

import (
	"fmt"
	"testing"

	"github.com/cerbos/cerbos/internal/test/e2e"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

func TestOverlay(t *testing.T) {
	// a rather hacky way simulate a SQLite error, by dropping tables
	postSetup := func(ctx e2e.Ctx) {
		// TODO dynamically retrieve var?
		db, err := sqlx.Connect("pgx", fmt.Sprintf("postgres://postgres:passw0rd@%s.%s.svc.cluster.local:5432/postgres?sslmode=disable&search_path=cerbos", ctx.ContextID, ctx.Namespace()))
		require.NoError(t, err, "failed to connect to postgres")

		txn := db.MustBegin()
		txn.MustExec("DROP TABLE IF EXISTS policy CASCADE;")
		err = txn.Commit()
		require.NoError(t, err, "failed to drop tables from test postgres db")
	}

	t.Run("base driver success", func(t *testing.T) {
		// TODO change contextID?
		e2e.RunSuites(t, e2e.WithContextID("postgres"), e2e.WithImmutableStoreSuites())
	})

	t.Run("base driver error and fallback driver success", func(t *testing.T) {
		// TODO change contextID?
		// TODO retrieve fallbackErrorThreshold from the config - if they're equal, this will pass
		e2e.RunSuites(t, e2e.WithContextID("postgres"), e2e.WithImmutableStoreSuites(), e2e.WithPostSetup(postSetup), e2e.WithOverlayMaxRetries(1))
	})
}
