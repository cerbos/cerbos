// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlserver

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

//go:embed schema.sql
var schemaSQL []byte

const password = "MyPassword1!"

func TestSqlServer(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	is := require.New(t)
	pool, err := dockertest.NewPool("")
	is.NoError(err, "Could not connect to docker: %s", err)

	options := &dockertest.RunOptions{
		Repository: "mcr.microsoft.com/azure-sql-edge",
		Tag:        "latest",
		CapAdd:     []string{"SYS_PTRACE"},
		Env:        []string{"ACCEPT_EULA=1", "MSSQL_SA_PASSWORD=" + password},
	}

	resource, err := pool.RunWithOptions(options)
	is.NoError(err, "Could not start resource: %s", err)

	t.Cleanup(func() {
		if err := pool.Purge(resource); err != nil {
			t.Errorf("Failed to cleanup resources: %v", err)
		}
	})

	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Minute)
	}

	ctx, cancelFunc := context.WithDeadline(context.Background(), deadline)
	defer cancelFunc()

	port := resource.GetPort("1433/tcp")
	getConnString := func(dbname string) string {
		return fmt.Sprintf("sqlserver://sa:%s@127.0.0.1:%s?database=%s", password, port, dbname)
	}

	is.NoError(pool.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}

		db, err := sqlx.Connect("sqlserver", getConnString("master"))
		if err != nil {
			return err
		}

		return CreateSchema(bytes.NewReader(schemaSQL), db, func() (*sqlx.DB, error) {
			return sqlx.Connect("sqlserver", getConnString("cerbos"))
		})
	}), "Container did not start or couldn't create schema")

	store, err := NewStore(ctx, &Conf{
		URL: fmt.Sprintf("sqlserver://cerbos_user:ChangeMe(1!!)@127.0.0.1:%s?database=cerbos", port),
		ConnPool: &internal.ConnPoolConf{
			MaxLifetime: 1 * time.Minute,
			MaxIdleTime: 45 * time.Second,
			MaxOpen:     4,
			MaxIdle:     1,
		},
	})
	require.NoError(t, err)

	t.Run("check schema", func(t *testing.T) {
		internal.TestCheckSchema(ctx, t, store)
	})

	t.Run("suite", internal.TestSuite(store))
}
