// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/storage"
	"go.uber.org/multierr"
)

const (
	confKey                  = storage.ConfKey + "." + DriverName
	defaultCacheSize         = 1024
	defaultHeartbeatInterval = 180 * time.Second
	defaultMaxRetryWait      = 120 * time.Second
	defaultMinRetryWait      = 1 * time.Second
	defaultNumRetries        = 5
	minHeartbeatInterval     = 30 * time.Second
)

var (
	ErrDuplicateCredentials = errors.New("both cerbosHub.credentials and storage.bundle.credentials are defined: please use cerbosHub.credentials")
	ErrNoSource             = errors.New("at least one of local or remote sources must be defined")
)

// Conf is required (if driver is set to 'bundle') configuration for bundle storage driver.
// +desc=This section is required only if storage.driver is bundle.
type Conf struct {
	// Remote holds configuration for remote bundle source. Takes precedence over local if both are defined.
	Remote *RemoteSourceConf `yaml:"remote"`
	// Local holds configuration for local bundle source.
	Local *LocalSourceConf `yaml:"local"`
	// Credentials holds bundle source credentials.
	Credentials hub.CredentialsConf `yaml:"credentials" conf:",ignore"`
	// CacheSize defines the number of policies to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",example=1024"`
}

// LocalSourceConf holds configuration for local bundle store.
type LocalSourceConf struct {
	// BundlePath is the full path to the local bundle file.
	BundlePath string `yaml:"bundlePath" conf:"required,example=/path/to/bundle.crbp"`
	// TempDir is the directory to use for temporary files.
	TempDir string `yaml:"tempDir" conf:",example=${TEMP}"`
}

// RemoteSourceConf holds configuration for remote bundle store.
type RemoteSourceConf struct {
	// BundleLabel to fetch from the server.
	BundleLabel string `yaml:"bundleLabel" conf:"required,example=latest"`
	// CacheDir is the directory to use for caching downloaded bundles.
	CacheDir string `yaml:"cacheDir" conf:",example=${XDG_CACHE_DIR}"`
	// TempDir is the directory to use for temporary files.
	TempDir string `yaml:"tempDir" conf:",example=${TEMP}"`
	// Connection defines settings for the remote server connection.
	Connection ConnectionConf `yaml:"connection"`
	// DisableAutoUpdate sets whether new bundles should be automatically downloaded and applied.
	DisableAutoUpdate bool `yaml:"disableAutoUpdate"`
}

// ConnectionConf holds configuration for the remote connection.
type ConnectionConf struct {
	// TLS defines settings for TLS connections.
	TLS TLSConf `yaml:"tls"`
	// APIEndpoint is the address of the API server.
	APIEndpoint string `yaml:"apiEndpoint" conf:"required,example=https://api.cerbos.cloud"`
	// BootstrapEndpoint is the addresses of the server serving the bootstrap configuration.
	BootstrapEndpoint string `yaml:"bootstrapEndpoint" conf:"required,example=https://cdn.cerbos.cloud"`
	// MinRetryWait is the minimum amount of time to wait between retries.
	MinRetryWait time.Duration `yaml:"minRetryWait" conf:",example=1s"`
	// MaxRetryWait is the maximum amount of time to wait between retries.
	MaxRetryWait time.Duration `yaml:"maxRetryWait" conf:",example=120s"`
	// NumRetries is the number of times to retry before giving up.
	NumRetries uint `yaml:"numRetries" conf:",example=5"`
	// HeartbeatInterval is the interval for sending regular heartbeats.
	HeartbeatInterval time.Duration `yaml:"heartbeatInterval" conf:",example=2m"`
}

func (cc *ConnectionConf) setDefaultsForUnsetFields() {
	if cc.APIEndpoint == "" {
		cc.APIEndpoint = hub.DefaultAPIEndpoint
	}

	if cc.BootstrapEndpoint == "" {
		cc.BootstrapEndpoint = hub.DefaultBootstrapHost
	}

	if cc.MinRetryWait == 0 {
		cc.MinRetryWait = defaultMinRetryWait
	}

	if cc.MaxRetryWait == 0 {
		cc.MaxRetryWait = defaultMaxRetryWait
	}

	if cc.NumRetries == 0 {
		cc.NumRetries = defaultNumRetries
	}

	switch {
	case cc.HeartbeatInterval < 0:
		cc.HeartbeatInterval = 0
	case cc.HeartbeatInterval == 0:
		cc.HeartbeatInterval = defaultHeartbeatInterval
	case cc.HeartbeatInterval > 0 && cc.HeartbeatInterval < minHeartbeatInterval:
		cc.HeartbeatInterval = minHeartbeatInterval
	}
}

// TLSConf holds TLS configuration for the remote connection.
type TLSConf struct {
	// Authority overrides the Cerbos PDP server authority if it is different from what is provided in the address.
	Authority string `yaml:"authority" conf:",example=domain.tld"`
	// CACert is the path to the CA certificate chain to use for certificate verification.
	CACert string `yaml:"caCert" conf:",example=/path/to/CA_certificate"`
}

func (conf *Conf) Key() string {
	return confKey
}

func (conf *Conf) SetDefaults() {
	conf.CacheSize = defaultCacheSize
}

func (conf *Conf) Validate() (outErr error) {
	if conf.Local == nil && conf.Remote == nil {
		return ErrNoSource
	}

	if conf.CacheSize == 0 {
		outErr = multierr.Append(outErr, errors.New("cacheSize must be greater than zero"))
	}

	if err := conf.Local.validate(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	if err := conf.Remote.validate(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	if err := conf.validateCredentials(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	return outErr
}

func (conf *Conf) validateCredentials() error {
	hubConf, err := hub.GetConf()
	if err != nil {
		return fmt.Errorf("failed to read Cerbos Hub configuration: %w", err)
	}

	switch {
	case hubConf.Credentials.IsUnset():
		return conf.Credentials.Validate()
	case conf.Credentials.IsUnset():
		conf.Credentials = hubConf.Credentials
		return conf.Credentials.Validate()
	default:
		return ErrDuplicateCredentials
	}
}

func (lc *LocalSourceConf) validate() error {
	if lc == nil {
		return nil
	}

	stat, err := os.Stat(lc.BundlePath)
	if err != nil {
		return fmt.Errorf("failed to stat localSource.bundlePath %q: %w", lc.BundlePath, err)
	}

	if stat.IsDir() || stat.Size() == 0 {
		return fmt.Errorf("localSource.bundlePath %q is empty or a directory", lc.BundlePath)
	}

	return nil
}

func (lc *LocalSourceConf) setDefaultsForUnsetFields() error {
	if lc == nil {
		return errors.New("configuration is undefined")
	}

	if lc.TempDir == "" {
		dir, err := os.MkdirTemp("", "cerbos-hub-*")
		if err != nil {
			return fmt.Errorf("failed to create temporary directory: %w", err)
		}
		lc.TempDir = dir
	}

	return nil
}

func (rc *RemoteSourceConf) validate() error {
	if rc == nil {
		return nil
	}

	if rc.BundleLabel == "" {
		rc.BundleLabel = hub.GetEnv(hub.BundleLabelKey)
	}

	if strings.TrimSpace(rc.BundleLabel) == "" {
		return errors.New("bundleLabel must be specified")
	}

	return nil
}

func (rc *RemoteSourceConf) setDefaultsForUnsetFields() error {
	if rc == nil {
		return errors.New("configuration is undefined")
	}

	if rc.BundleLabel == "" {
		rc.BundleLabel = hub.GetEnv(hub.BundleLabelKey)
	}

	if rc.TempDir == "" {
		dir, err := os.MkdirTemp("", "cerbos-hub-*")
		if err != nil {
			return fmt.Errorf("failed to create temporary directory: %w", err)
		}
		rc.TempDir = dir
	}

	if rc.CacheDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("failed to determine cache directory: %w", err)
		}

		dir := filepath.Join(cacheDir, "cerbos-hub")
		//nolint:gomnd
		if err := os.MkdirAll(dir, 0o764); err != nil {
			return fmt.Errorf("failed to create cache dir %q: %w", dir, err)
		}

		rc.CacheDir = dir
	}

	rc.Connection.setDefaultsForUnsetFields()
	return nil
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
