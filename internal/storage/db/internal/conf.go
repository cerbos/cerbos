// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package internal

import (
	"errors"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/jmoiron/sqlx"
)

const (
	defaultRetryMaxAttempts uint = 3
)

// ConnPoolConf holds common SQL connection pool settings.
type ConnPoolConf struct {
	MaxLifetime time.Duration `yaml:"maxLifeTime"`
	MaxIdleTime time.Duration `yaml:"maxIdleTime"`
	MaxOpen     uint          `yaml:"maxOpen"`
	MaxIdle     uint          `yaml:"maxIdle"`
}

func (cc *ConnPoolConf) Configure(db *sqlx.DB) {
	if cc == nil {
		return
	}

	db.SetConnMaxLifetime(cc.MaxLifetime)
	db.SetConnMaxIdleTime(cc.MaxIdleTime)
	db.SetMaxIdleConns(int(cc.MaxIdle))
	db.SetMaxOpenConns(int(cc.MaxOpen))
}

// ConnRetryConf holds common retry settings for establishing a database connection.
type ConnRetryConf struct {
	// MaxAttempts is the maximum number of times to attempt to connect before giving up.
	MaxAttempts uint `yaml:"maxAttempts"`
	// InitialInterval is the initial wait period between retry attempts. Subsequent attempts will be longer depending on the attempt number.
	InitialInterval time.Duration `yaml:"initialInterval"`
	// MaxInterval is the maximum amount of time to wait between retry attempts.
	MaxInterval time.Duration `yaml:"maxInterval"`
}

func (rc *ConnRetryConf) Validate() (outErr error) {
	if rc == nil {
		return nil
	}

	if rc.InitialInterval < 0 {
		outErr = errors.Join(outErr, errors.New("retry.initialInterval must be a positive value"))
	}

	if rc.MaxInterval < 0 {
		outErr = errors.Join(outErr, errors.New("retry.maxInterval must be a positive value"))
	}

	if rc.MaxInterval < rc.InitialInterval {
		outErr = errors.Join(outErr, errors.New("retry.maxInterval must be larger than retry.initialInterval"))
	}

	return outErr
}

func (rc *ConnRetryConf) BackoffOptions() []backoff.RetryOption {
	b := backoff.NewExponentialBackOff()
	maxAttempts := defaultRetryMaxAttempts

	if rc != nil {
		if rc.MaxInterval > 0 {
			b.MaxInterval = rc.MaxInterval
		}

		if rc.InitialInterval > 0 {
			b.InitialInterval = rc.InitialInterval
		}

		if rc.MaxAttempts > 0 {
			maxAttempts = rc.MaxAttempts
		}
	}

	return []backoff.RetryOption{
		backoff.WithBackOff(b),
		backoff.WithMaxTries(maxAttempts),
	}
}
