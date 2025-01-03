// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package mysql_test

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage/db/internal"
	"github.com/cerbos/cerbos/internal/storage/db/mysql"
	"github.com/ory/dockertest/v3"
)

//go:embed schema.sql
var schemaSQL []byte

func TestMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "Failed to connect to Docker")

	resource, err := pool.Run("mysql", "8", []string{"MYSQL_ROOT_PASSWORD=secret"})
	require.NoError(t, err, "Failed to start container")

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

	rootDSN := fmt.Sprintf("root:secret@(localhost:%s)/mysql", resource.GetPort("3306/tcp"))
	require.NoError(t, pool.Retry(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}

		db, err := sqlx.Connect("mysql", rootDSN)
		if err != nil {
			return err
		}

		return createSchema(db)
	}), "Container did not start")

	store, err := mysql.NewStore(ctx, &mysql.Conf{
		DSN: fmt.Sprintf("cerbos_user:changeme@tcp(localhost:%s)/cerbos?parseTime=true", resource.GetPort("3306/tcp")),
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

func createSchema(db *sqlx.DB) error {
	s := bufio.NewScanner(bytes.NewReader(schemaSQL))
	s.Split(splitOnSemicolons)

	for s.Scan() {
		query := s.Text()
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute [%s]: %w", query, err)
		}
	}

	return s.Err()
}

func splitOnSemicolons(data []byte, atEOF bool) (int, []byte, error) {
	// no more data to process
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// found a semicolon
	if i := bytes.IndexByte(data, ';'); i >= 0 {
		return i + 1, bytes.TrimSpace(data[:i+1]), nil
	}

	// at the end of input
	if atEOF {
		return len(data), bytes.TrimSpace(data), nil
	}

	// get more data
	return 0, nil, nil
}
