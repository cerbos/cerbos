// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/doug-martin/goqu/v9"

	// import sqlite3 dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/sqlite3"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	// import sqlite3 driver.
	_ "modernc.org/sqlite"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const DriverName = "sqlite3"

//go:embed schema.sql
var schema string

var _ storage.MutableStore = (*Store)(nil)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context) (storage.Store, error) {
		conf := &Conf{}
		if err := config.GetSection(conf); err != nil {
			return nil, err
		}

		return NewStore(ctx, conf)
	})
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	log := logging.FromContext(ctx).Named("sqlite3")
	log.Info("Initializing sqlite3 storage", zap.String("DSN", conf.DSN))

	db, err := sqlx.Connect("sqlite", conf.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.ExecContext(ctx, schema, nil); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	storage, err := internal.NewDBStorage(ctx, goqu.New("sqlite3", db))
	if err != nil {
		return nil, err
	}

	return &Store{DBStorage: storage}, nil
}

type Store struct {
	internal.DBStorage
}

func (s *Store) Driver() string {
	return DriverName
}
