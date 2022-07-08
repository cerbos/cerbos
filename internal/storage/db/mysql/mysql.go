// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/jmoiron/sqlx"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const DriverName = "mysql"

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
	log := logging.FromContext(ctx).Named("mysql")
	log.Info("Initializing MySQL storage")

	dsn, err := buildDSN(conf)
	if err != nil {
		return nil, err
	}

	db, err := sqlx.Connect("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	conf.ConnPool.Configure(db)

	storage, err := internal.NewDBStorage(ctx, goqu.New("mysql", db))
	if err != nil {
		return nil, err
	}

	return &Store{DBStorage: storage}, nil
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

type Store struct {
	internal.DBStorage
}

func (s *Store) Driver() string {
	return DriverName
}
