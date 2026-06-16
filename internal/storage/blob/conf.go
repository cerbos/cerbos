// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package blob

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/multierr"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	confKey                = storage.ConfKey + "." + DriverName
	defaultDownloadTimeout = 60 * time.Second
	defaultRequestTimeout  = 5 * time.Second
)

// Conf is required (if driver is set to 'blob') configuration for cloud storage driver.
// +desc=This section is required only if storage.driver is blob.
type Conf struct {
	// DownloadTimeout specifies the timeout for downloading from cloud storage.
	DownloadTimeout *time.Duration `yaml:"downloadTimeout,omitempty" conf:",example=30s"`
	// RequestTimeout specifies the timeout for an HTTP request.
	RequestTimeout *time.Duration `yaml:"requestTimeout,omitempty" conf:",example=10s"`
	// Bucket URL (Examples: s3://my-bucket?region=us-west-1 gs://my-bucket).
	Bucket string `yaml:"bucket" conf:"required,example=\"s3://my-bucket-name?region=us-east-2\""`
	// Prefix specifies a subdirectory to download.
	Prefix string `yaml:"prefix,omitempty" conf:",example=policies"`
	// WorkDir is the local path to check out policies to.
	WorkDir string `yaml:"workDir" conf:",example=${HOME}/tmp/cerbos/work"`
	// UpdatePollInterval specifies the interval to poll the cloud storage. Set to 0 to disable.
	UpdatePollInterval time.Duration `yaml:"updatePollInterval" conf:",example=15s"`
}

func (conf *Conf) Key() string {
	return confKey
}

func (conf *Conf) Validate() error {
	var errs []error

	if conf.Bucket == "" {
		errs = append(errs, errors.New("bucket is required"))
	}

	if conf.WorkDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			errs = append(errs, fmt.Errorf("workDir unspecified and failed to determine user cache dir: %w", err))
		} else {
			conf.WorkDir = filepath.Join(cacheDir, util.AppName, DriverName)
		}
	}

	if *conf.RequestTimeout > *conf.DownloadTimeout {
		errs = append(errs, fmt.Errorf("request timeout (%.0fs) is greater than download timeout (%.0fs)", conf.RequestTimeout.Seconds(), conf.DownloadTimeout.Seconds()))
	}

	if len(errs) > 0 {
		return multierr.Combine(errs...)
	}

	return nil
}

func pd(d time.Duration) *time.Duration {
	return &d
}

func (conf *Conf) SetDefaults() {
	if conf.RequestTimeout == nil {
		conf.RequestTimeout = pd(defaultRequestTimeout)
	}
	if conf.DownloadTimeout == nil {
		conf.DownloadTimeout = pd(defaultDownloadTimeout)
	}
}

func (conf *Conf) getCloneCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, *conf.DownloadTimeout)
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
