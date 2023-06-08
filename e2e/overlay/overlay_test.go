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

const fallbackErrThreshold = 1

func TestOverlay(t *testing.T) {
	t.Log(">>> Loading policies into Postgres using the cerbos-admin instance")
	computedEnv := func(ctx e2e.Ctx) map[string]string {
		return map[string]string{
			"E2E_DATABASE_URL":           dbURL(ctx),
			"E2E_CERBOS_HOST":            fmt.Sprintf("cerbos-admin-%s.%s", ctx.ContextID, ctx.Namespace()),
			"E2E_FALLBACK_ERR_THRESHOLD": strconv.FormatInt(fallbackErrThreshold, 10),
		}
	}
	e2e.RunSuites(t, e2e.WithContextID("overlay"), e2e.WithSuites(e2e.AdminSuite), e2e.WithComputedEnv(computedEnv))

	computedEnv = func(ctx e2e.Ctx) map[string]string {
		return map[string]string{
			"E2E_DATABASE_URL":           dbURL(ctx),
			"E2E_FALLBACK_ERR_THRESHOLD": strconv.FormatInt(fallbackErrThreshold, 10),
		}
	}

	t.Log(">>> Testing the overlay base driver")
	e2e.RunSuites(t, e2e.WithContextID("overlay"), e2e.WithImmutableStoreSuites(), e2e.WithComputedEnv(computedEnv))
	t.Log(">>> Testing the overlay fallback driver")
	e2e.RunSuites(t, e2e.WithContextID("overlay"), e2e.WithImmutableStoreSuites(), e2e.WithComputedEnv(computedEnv), e2e.WithPostSetup(breakDB(t)), e2e.WithOverlayMaxRetries(fallbackErrThreshold))
}

func dbURL(ctx e2e.Ctx) string {
	return fmt.Sprintf("postgres://postgres:passw0rd@postgres-%s.%s.svc.cluster.local:5432/postgres?sslmode=disable&search_path=cerbos", ctx.ContextID, ctx.Namespace())
}

func breakDB(t *testing.T) func(e2e.Ctx) {
	t.Helper()
	return func(ctx e2e.Ctx) {
		// a rather hacky way simulate a DB error, by dropping tables
		db, err := sqlx.Connect("pgx", dbURL(ctx))
		require.NoError(t, err, "failed to connect to postgres")

		txn := db.MustBegin()
		txn.MustExec("DROP TABLE IF EXISTS policy CASCADE;")
		err = txn.Commit()
		require.NoError(t, err, "failed to drop tables from test postgres db")
	}
}
