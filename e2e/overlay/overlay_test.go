// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package overlay_test

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
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
			"E2E_CERBOS_HOST":            fmt.Sprintf("cerbos-admin-%s.%s.svc.cluster.local", ctx.ContextID, ctx.Namespace()),
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
	e2e.RunSuites(t, e2e.WithContextID("overlay"), e2e.WithImmutableStoreSuites(), e2e.WithComputedEnv(computedEnv), e2e.WithPostSetup(reloadStore(t)))

	t.Log(">>> Testing the overlay fallback driver")
	e2e.RunSuites(t, e2e.WithContextID("overlay"), e2e.WithImmutableStoreSuites(), e2e.WithComputedEnv(computedEnv), e2e.WithPostSetup(breakDB(t)), e2e.WithPostSetup(reloadStore(t)), e2e.WithOverlayMaxRetries(fallbackErrThreshold))
}

func dbURL(ctx e2e.Ctx) string {
	return fmt.Sprintf("postgres://postgres:passw0rd@postgres-%s.%s.svc.cluster.local:5432/postgres?sslmode=disable&search_path=cerbos", ctx.ContextID, ctx.Namespace())
}

// breakDB drops the policy table to break the base storage driver 'postgres'.
// This operation alone doesn't trigger Cerbos to read policies from the fallback driver because the rule table
// implementation reads everything from base storage driver 'postgres' into memory on start-up only. Thus, a store reload
// is required to see the effect.
func breakDB(t *testing.T) func(e2e.Ctx) {
	t.Helper()
	return func(ctx e2e.Ctx) {
		db, err := sqlx.Connect("pgx", dbURL(ctx))
		require.NoError(t, err, "failed to connect to postgres")

		txn := db.MustBegin()
		txn.MustExec("DROP TABLE IF EXISTS policy CASCADE;")
		err = txn.Commit()
		require.NoError(t, err, "failed to drop tables from test postgres db")
	}
}

func reloadStore(t *testing.T) func(e2e.Ctx) {
	t.Helper()
	return func(ctx e2e.Ctx) {
		client := mkClient(t)

		req, err := http.NewRequest(
			http.MethodGet,
			fmt.Sprintf("%s/admin/store/reload?wait=true", ctx.HTTPAddr()),
			nil,
		)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("cerbos:cerbosAdmin")))

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func mkClient(t *testing.T) *http.Client {
	t.Helper()

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: tr}
}
