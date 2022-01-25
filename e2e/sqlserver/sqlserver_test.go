// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package sqlserver_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/test/e2e"
	"github.com/cerbos/cerbos/internal/storage/db/sqlserver"
	"os"
	"path"
	"fmt"
	"github.com/jmoiron/sqlx"
)

const password = "MyPassword1!"

func TestSqlServer(t *testing.T) {
	dir, err := sqlserver.PathToDir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path.Join(dir, "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	postSetup := func(ctx e2e.Ctx) {
		sqlserverEndpoint := fmt.Sprintf("mssqllatest-%s.%s:1433", ctx.ContextID, ctx.Namespace())
		getConnString := func(dbname string) string {
			return fmt.Sprintf("sqlserver://sa:%s@%s?database=%s", password, sqlserverEndpoint, dbname)
		}

		db, err := sqlx.Connect("sqlserver", getConnString("master"))
		if err != nil {
			t.Fatal("couldn't connect to sqlserver", err)
		}
		t.Log("connected to sqlserver")
		err = sqlserver.CreateSchema(f, db, func() (*sqlx.DB, error) {
			return sqlx.Connect("sqlserver", getConnString("cerbos"))
		})
		if err != nil {
			t.Fatal("couldn't create schema", err)
		}
	}
	e2e.RunSuites(t, e2e.WithContextID("sqlserver"), e2e.WithMutableStoreSuites(), e2e.WithPostSetup(postSetup))
}
