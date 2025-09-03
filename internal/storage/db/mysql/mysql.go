// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package mysql

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/doug-martin/goqu/v9"

	// Import the MySQL dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/mysql"
	"github.com/go-sql-driver/mysql"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const (
	DriverName                 = "mysql"
	urlToSchemaDocs            = "https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#mysql-schema"
	constraintViolationErrCode = 1062
)

var (
	_ storage.SourceStore  = (*Store)(nil)
	_ storage.MutableStore = (*Store)(nil)
	_ storage.Subscribable = (*Store)(nil)
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
	log := logging.FromContext(ctx).Named("mysql")
	log.Info("Initializing MySQL storage")

	dsn, err := buildDSN(conf)
	if err != nil {
		return nil, err
	}

	db, err := internal.ConnectWithRetries(ctx, "mysql", dsn, conf.ConnRetry)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	conf.ConnPool.Configure(db)

	s, err := internal.NewDBStorage(ctx, goqu.New("mysql", db), internal.WithUpsertPolicy(upsertPolicy), internal.WithSourceAttributes(policy.SourceDriver(DriverName)))
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
					Driver: auditv1.PolicySource_Database_DRIVER_MYSQL,
				},
			},
		},
	}, nil
}

func buildDSN(conf *Conf) (string, error) {
	if err := registerTLS(conf); err != nil {
		return "", err
	}

	if err := registerServerPubKeys(conf); err != nil {
		return "", err
	}

	dbConf, err := mysql.ParseDSN(conf.DSN)
	if err != nil {
		return "", fmt.Errorf("failed to parse DSN: %w", err)
	}

	return dbConf.FormatDSN(), nil
}

func registerTLS(conf *Conf) error {
	for name, tlsConf := range conf.TLS {
		cert, err := tls.LoadX509KeyPair(tlsConf.Cert, tlsConf.Key)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		// Most MySQL versions have not caught up to modern TLS settings so we can't use utils.DefaultTLSConfig here.
		c := &tls.Config{Certificates: []tls.Certificate{cert}} //nolint:gosec

		if tlsConf.CACert != "" {
			caPEM, err := os.ReadFile(tlsConf.CACert)
			if err != nil {
				return fmt.Errorf("failed to load CA certificate: %w", err)
			}

			certPool := x509.NewCertPool()
			if ok := certPool.AppendCertsFromPEM(caPEM); !ok {
				return errors.New("failed to add CA certificate to pool")
			}

			c.RootCAs = certPool
		}

		if err := mysql.RegisterTLSConfig(name, c); err != nil {
			return err
		}
	}
	return nil
}

func registerServerPubKeys(conf *Conf) error {
	for name, pkPath := range conf.ServerPubKey {
		data, err := os.ReadFile(pkPath)
		if err != nil {
			return fmt.Errorf("failed to read public key from [%s]: %w", pkPath, err)
		}

		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" {
			return fmt.Errorf("file does not contain a valid public key: %s", pkPath)
		}

		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key; %w", err)
		}

		rsaPK, ok := pk.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("file does not contain a RSA public key: %s", pkPath)
		}

		mysql.RegisterServerPubKey(name, rsaPK)
	}
	return nil
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

	if _, err := tx.Insert(internal.PolicyTbl).Prepared(true).Rows(pr).Executor().ExecContext(ctx); err != nil {
		mysqlErr := new(mysql.MySQLError)
		if !errors.As(err, &mysqlErr) || mysqlErr.Number != constraintViolationErrCode {
			return fmt.Errorf("failed to insert policy %s: %w", p.FQN, err)
		}

		// Check if the existing policy name matches the name of the policy we are trying to insert.
		// The reason for not doing an UPDATE WHERE and checking the number of affected rows is because MySQL
		// returns 0 if the update did not change any of the columns as well.
		var existingName string
		ok, err := tx.Select(goqu.C(internal.PolicyTblNameCol)).
			From(internal.PolicyTbl).
			Where(goqu.C(internal.PolicyTblIDCol).Eq(pr.ID)).
			Executor().ScanValContext(ctx, &existingName)
		if !ok || err != nil {
			return fmt.Errorf("failed to lookup policy %s: %w", p.FQN, err)
		}

		if existingName != pr.Name {
			return fmt.Errorf("failed to insert policy %s.%s: %w", p.Name, p.Version, storage.ErrPolicyIDCollision)
		}

		// attempt update
		if _, err := tx.Update(internal.PolicyTbl).
			Prepared(true).
			Set(pr).
			Where(goqu.And(
				goqu.C(internal.PolicyTblIDCol).Eq(pr.ID),
				goqu.C(internal.PolicyTblNameCol).Eq(pr.Name),
			)).Executor().ExecContext(ctx); err != nil {
			return fmt.Errorf("failed to update policy %s: %w", p.FQN, err)
		}

		return nil
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
