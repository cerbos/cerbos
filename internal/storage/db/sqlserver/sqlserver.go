// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlserver

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	// Import the mssql driver.
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/doug-martin/goqu/v9"

	// Import the mssql dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/sqlserver"
	"github.com/jmoiron/sqlx"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const DriverName = "sqlserver"

var _ storage.MutableStore = (*Store)(nil)

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
	log := logging.FromContext(ctx).Named("sqlserver")
	log.Info("Initialising SQL Server storage")

	db, err := sqlx.Connect(DriverName, conf.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conf.ConnPool.Configure(db)

	dbStorage, err := internal.NewDBStorage(ctx, goqu.New("sqlserver", db), internal.WithUpsertPolicy(upsertPolicy), internal.WithUpsertSchema(upsertSchema))
	if err != nil {
		return nil, err
	}

	return &Store{DBStorage: dbStorage}, nil
}

type Store struct {
	internal.DBStorage
}

func (s *Store) Driver() string {
	return DriverName
}

func upsertPolicy(ctx context.Context, tx *goqu.TxDatabase, p policy.Wrapper) error {
	stm, err := tx.Prepare(`
UPDATE dbo.[policy] WITH (UPDLOCK, SERIALIZABLE) SET "definition"=@definition, "description"=@description,"disabled"=@disabled,"kind"=@kind,"name"=@name,"version"=@version,"scope"=@scope where [id] = @id 
IF @@ROWCOUNT = 0
BEGIN
  INSERT INTO dbo.[policy] ("definition", "description", "disabled", "kind", "name", "version", "scope", "id") VALUES (@definition, @description, @disabled, @kind, @name, @version, @scope, @id)
END
`)
	if err != nil {
		return fmt.Errorf("failed to prepare policy upsert %s: %w", p.FQN, err)
	}

	defer stm.Close()

	definition, err := internal.PolicyDefWrapper{Policy: p.Policy}.Value()
	if err != nil {
		return fmt.Errorf("failed to get definition value: %w", err)
	}

	id, _ := p.ID.Value()

	_, err = stm.ExecContext(ctx,
		sql.Named("definition", definition),
		sql.Named("description", p.Description),
		sql.Named("disabled", p.Disabled),
		sql.Named("kind", p.Kind.String()),
		sql.Named("name", p.Name),
		sql.Named("version", p.Version),
		sql.Named("scope", p.Scope),
		sql.Named("id", int64(id.(uint64))))

	return err
}

func upsertSchema(ctx context.Context, tx *goqu.TxDatabase, schema internal.Schema) error {
	stm, err := tx.Prepare(`
UPDATE dbo.[attr_schema_defs] WITH (UPDLOCK, SERIALIZABLE) SET "definition"=@definition WHERE [id] = @id 
IF @@ROWCOUNT = 0
BEGIN
  INSERT INTO dbo.[attr_schema_defs] ("definition", "id") VALUES (@definition, @id)
END
`)
	if err != nil {
		return fmt.Errorf("failed to prepare schema upsert %s: %w", schema.ID, err)
	}

	defer stm.Close()

	definition, err := schema.Definition.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal defJson: %w", err)
	}
	_, err = stm.ExecContext(ctx, sql.Named("definition", definition), sql.Named("id", schema.ID))

	return err
}

func CreateSchema(r io.Reader, db *sqlx.DB, f func() (*sqlx.DB, error)) error {
	s := bufio.NewScanner(r)
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
			continue
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

func PathToDir() (string, error) {
	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("failed to detect path")
	}

	return filepath.Dir(currFile), nil
}
