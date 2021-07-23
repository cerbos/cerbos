// Copyright 2021 Zenauth Ltd.

package postgres_test

import (
	"context"
	_ "embed"
	"fmt"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v4"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage/db/internal"
	"github.com/cerbos/cerbos/internal/storage/db/postgres"
	"github.com/cerbos/cerbos/internal/util"
)

//go:embed schema.sql
var schemaSQL string

func TestPostgres(t *testing.T) {
	port, err := util.GetFreePort()
	require.NoError(t, err, "Failed to get free port")

	pgConf := embeddedpostgres.DefaultConfig().Port(uint32(port))
	pg := embeddedpostgres.NewDatabase(pgConf)
	require.NoError(t, pg.Start(), "Failed to start Postgres")

	defer func() {
		if err := pg.Stop(); err != nil {
			t.Errorf("Failed to stop Postgres: %v", err)
		}
	}()

	createSchema(t, fmt.Sprintf("postgres://postgres:postgres@localhost:%d?sslmode=disable", port))

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	connURL := fmt.Sprintf("postgres://cerbos_user:changeme@localhost:%d/postgres?sslmode=disable&search_path=cerbos", port)
	store, err := postgres.NewStore(ctx, &postgres.Conf{URL: connURL})
	require.NoError(t, err)

	t.Run("suite", internal.TestSuite(store))
}

func createSchema(t *testing.T, url string) {
	t.Helper()

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	conn, err := pgx.Connect(ctx, url)
	require.NoError(t, err)

	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, schemaSQL)
	require.NoError(t, err, "Failed to create schema")
}
