// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlserver_test

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage/db/internal"
	"github.com/cerbos/cerbos/internal/storage/db/sqlserver"
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

		return createSchema(db, func() (*sqlx.DB, error) {
			return sqlx.Connect("sqlserver", getConnString("cerbos"))
		})
	}), "Container did not start or couldn't create schema")

	store, err := sqlserver.NewStore(ctx, &sqlserver.Conf{
		URL: fmt.Sprintf("sqlserver://cerbos_user:ChangeMe(1!!)@127.0.0.1:%s?database=cerbos", port),
		ConnPool: &internal.ConnPoolConf{
			MaxLifetime: 1 * time.Minute,
			MaxIdleTime: 45 * time.Second,
			MaxOpen:     4,
			MaxIdle:     1,
		},
	})
	require.NoError(t, err)
	t.Run("suite", internal.TestSuite(store))
}

func createSchema(db *sqlx.DB, f func() (*sqlx.DB, error)) error {
	s := bufio.NewScanner(bytes.NewReader(schemaSQL))
	s.Split(splitOnGo)
	var c *sqlx.DB
	var err error

	for s.Scan() {
		query := s.Text()

		if strings.HasPrefix(query, "CREATE TRIGGER") {
			if c == nil {
				c, err = f()
				if err != nil {
					return fmt.Errorf("failed to connect to \"cerbos\" database")
				}
			}
			if _, err = c.Exec(query); err != nil {
				return fmt.Errorf("failed to execute [%s]: %w", query, err)
			}
			break
		}

		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute [%s]: %w", query, err)
		}
	}

	return s.Err()
}

var sep = []byte("\nGO\n")

func splitOnGo(data []byte, atEOF bool) (int, []byte, error) {
	// no more data to process
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := bytes.Index(data, sep); i >= 0 {
		return i + len(sep), bytes.TrimSpace(data[:i-1]), nil
	}
	// at the end of input
	if atEOF {
		return len(data), bytes.TrimSpace(data), nil
	}

	// get more data
	return 0, nil, nil
}
