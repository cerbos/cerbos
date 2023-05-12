// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package overlay_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/cerbos/cerbos/internal/test/e2e"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

func TestOverlay(t *testing.T) {
	env := make(map[string]string)

	computedEnvFn := func(ctx e2e.Ctx) map[string]string {
		env["E2E_DATABASE_URL"] = fmt.Sprintf("postgres://postgres:passw0rd@%s.%s.svc.cluster.local:5432/postgres?sslmode=disable&search_path=cerbos", ctx.ContextID, ctx.Namespace())
		env["E2E_FALLBACK_ERR_THRESHOLD"] = "1"
		return env
	}

	// a rather hacky way simulate a DB error, by dropping tables
	breakDB := func(ctx e2e.Ctx) {
		db, err := sqlx.Connect("pgx", env["E2E_DATABASE_URL"])
		require.NoError(t, err, "failed to connect to postgres")

		txn := db.MustBegin()
		txn.MustExec("DROP TABLE IF EXISTS policy CASCADE;")
		err = txn.Commit()
		require.NoError(t, err, "failed to drop tables from test postgres db")
	}

	t.Run("base driver success", func(t *testing.T) {
		// TODO dedicated contextID?
		e2e.RunSuites(t, e2e.WithContextID("postgres"), e2e.WithImmutableStoreSuites(), e2e.WithComputedEnv(computedEnvFn))
	})

	fallbackErrorThreshold, err := strconv.ParseUint(env["E2E_FALLBACK_ERR_THRESHOLD"], 10, 64)
	require.NoError(t, err, "failed to convert fallbackErrorThreshold string to uint64")

	t.Run("base driver error and fallback driver success", func(t *testing.T) {
		// TODO dedicated contextID?
		e2e.RunSuites(t, e2e.WithContextID("postgres"), e2e.WithImmutableStoreSuites(), e2e.WithComputedEnv(computedEnvFn), e2e.WithPostSetup(breakDB), e2e.WithOverlayMaxRetries(fallbackErrorThreshold))
	})
}
