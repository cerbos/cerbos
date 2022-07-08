// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"

	"github.com/doug-martin/goqu/v9"

	// Import the postgres dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/postgres"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/zapadapter"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const DriverName = "postgres"

var (
	_ storage.SourceStore  = (*Store)(nil)
	_ storage.MutableStore = (*Store)(nil)
)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, err
		}

		return NewStore(ctx, conf)
	})
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	log := logging.FromContext(ctx).Named("postgres")

	pgConf, err := pgx.ParseConfig(conf.URL)
	if err != nil {
		log.Error("Failed to parse Postgres connection URL", zap.Error(err))
		return nil, err
	}

	pgConf.Logger = zapadapter.NewLogger(log)
	pgConf.LogLevel = pgx.LogLevelWarn

	log.Info("Initializing Postgres storage", zap.String("host", pgConf.Host), zap.String("database", pgConf.Database))

	connStr := stdlib.RegisterConnConfig(pgConf)
	db, err := sqlx.Connect("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conf.ConnPool.Configure(db)

	storage, err := internal.NewDBStorage(ctx, goqu.New("postgres", db))
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
