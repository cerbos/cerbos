// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"

	"github.com/doug-martin/goqu/v9"

	// Import the postgres dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/postgres"
	pgxzap "github.com/jackc/pgx-zap"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/pgx/v5/tracelog"
	"go.uber.org/zap"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const (
	DriverName      = "postgres"
	urlToSchemaDocs = "https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#postgres-schema"
)

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
	pgConf.Tracer = &tracelog.TraceLog{Logger: pgxzap.NewLogger(log), LogLevel: tracelog.LogLevelWarn}

	log.Info("Initializing Postgres storage", zap.String("host", pgConf.Host), zap.String("database", pgConf.Database))

	connStr := stdlib.RegisterConnConfig(pgConf)
	db, err := internal.ConnectWithRetries(ctx, "pgx", connStr, conf.ConnRetry)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conf.ConnPool.Configure(db)

	s, err := internal.NewDBStorage(ctx, goqu.New("postgres", db), internal.WithUpsertPolicy(upsertPolicy), internal.WithSourceAttributes(policy.SourceDriver(DriverName)))
	if err != nil {
		return nil, err
	}

	if !conf.SkipSchemaCheck {
		if err := s.CheckSchema(ctx); err != nil {
			return nil, fmt.Errorf("schema check failed. Ensure that the schema is correctly defined as documented at %s: %w", urlToSchemaDocs, err)
		}
	}

	return &Store{
		DBStorage: s,
		source: &auditv1.PolicySource{
			Source: &auditv1.PolicySource_Database_{
				Database: &auditv1.PolicySource_Database{
					Driver: auditv1.PolicySource_Database_DRIVER_POSTGRES,
				},
			},
		},
	}, nil
}

func upsertPolicy(ctx context.Context, tx *goqu.TxDatabase, p policy.Wrapper) error {
	pr := internal.Policy{
		ID:          p.ID,
		Kind:        p.Kind.String(),
		Name:        p.Name,
		Version:     p.Version,
		Scope:       p.Scope,
		Description: p.Description,
		Disabled:    p.Disabled,
		Definition:  internal.PolicyDefWrapper{Policy: p.Policy},
	}
	res, err := tx.Insert(goqu.T(internal.PolicyTbl).As("p")).
		Prepared(true).
		Rows(pr).
		OnConflict(
			goqu.DoUpdate(internal.PolicyTblIDCol, pr).
				Where(
					goqu.L("EXCLUDED." + internal.PolicyTblNameCol).Eq(goqu.L("p." + internal.PolicyTblNameCol)),
				),
		).
		Executor().ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to insert policy %s: %w", p.FQN, err)
	}

	if updated, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to check status of policy %s: %w", p.FQN, err)
	} else if updated != 1 {
		return fmt.Errorf("failed to update policy %s.%s: %w", p.Name, p.Version, storage.ErrPolicyIDCollision)
	}

	return nil
}

type Store struct {
	internal.DBStorage
	source *auditv1.PolicySource
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) Source() *auditv1.PolicySource {
	return s.source
}
