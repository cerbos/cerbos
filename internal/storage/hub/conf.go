// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package hub

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/multierr"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/hub"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	confKey          = storage.ConfKey + "." + DriverName
	defaultCacheSize = 1024
)

var ErrNoSource = errors.New("at least one of local or remote sources must be defined")

// Conf is required (if driver is set to 'hub') configuration for hub storage driver.
// +desc=This section is required only if storage.driver is hub.
type Conf struct {
	// Remote holds configuration for remote bundle source. Takes precedence over local if both are defined.
	Remote *RemoteSourceConf `yaml:"remote"`
	// Local holds configuration for local bundle source.
	Local *LocalSourceConf `yaml:"local"`
	// Credentials holds Cerbos Hub credentials.
	Credentials *hub.CredentialsConf `yaml:"credentials" conf:",ignore"`
	// CacheSize defines the number of policies to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",example=1024"`
}

// LocalSourceConf holds configuration for local bundle store.
type LocalSourceConf struct {
	// BundlePath is the full path to the local bundle file.
	BundlePath string `yaml:"bundlePath" conf:"required,example=/path/to/bundle.crbp"`
	// EncryptionKey is encryption key to decode the bundle. It must be string encoded.
	EncryptionKey string `yaml:"encryptionKey" conf:",ignore"`
	// TempDir is the directory to use for temporary files.
	TempDir string `yaml:"tempDir" conf:",example=${TEMP}"`
}

// RemoteSourceConf holds configuration for remote bundle store.
type RemoteSourceConf struct {
	// Connection defines settings for the remote server connection.
	Connection *hub.ConnectionConf `yaml:"connection" conf:",ignore"`
	// BundleLabel to fetch from the server.
	BundleLabel string `yaml:"bundleLabel" conf:"required,example=latest"`
	// DeploymentID to fetch from the server.
	DeploymentID string `yaml:"deploymentID" conf:",ignore"`
	// PlaygroundID to fetch from the server.
	PlaygroundID string `yaml:"playgroundID" conf:",ignore"`
	// CacheDir is the directory to use for caching downloaded bundles.
	CacheDir string `yaml:"cacheDir" conf:",example=${XDG_CACHE_DIR}"`
	// TempDir is the directory to use for temporary files.
	TempDir string `yaml:"tempDir" conf:",example=${TEMP}"`
	// DisableAutoUpdate sets whether new bundles should be automatically downloaded and applied.
	DisableAutoUpdate bool `yaml:"disableAutoUpdate" conf:",example=false"`
	// DisableBootstrap makes the PDP always fetch bundles using the API. If the API is down, the PDP won't be able to start.
	DisableBootstrap bool `yaml:"disableBootstrap" conf:",ignore"`
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
	if conf.Credentials != nil {
		util.DeprecationReplacedWarning("storage.bundle.credentials section", "hub.credentials")
		return errors.New("storage.bundle.credentials section is no longer supported")
	}

	hubConf, err := hub.GetConf()
	if err != nil {
		return fmt.Errorf("failed to read Cerbos Hub configuration: %w", err)
	}

	conf.Credentials = &hubConf.Credentials
	return conf.Credentials.Validate()
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

	return rc.setDefaultsForUnsetFields()
}

func (rc *RemoteSourceConf) setDefaultsForUnsetFields() error {
	if rc.BundleLabel == "" {
		rc.BundleLabel = hub.GetEnv(hub.BundleLabelKey)
	}

	if rc.DeploymentID == "" {
		rc.DeploymentID = hub.GetEnv(hub.DeploymentIDKey)
	}

	if rc.PlaygroundID == "" {
		rc.PlaygroundID = hub.GetEnv(hub.PlaygroundIDKey)
	}

	if rc.BundleLabel == "" && rc.DeploymentID == "" && rc.PlaygroundID == "" {
		return errors.New("bundleLabel, deploymentID or playgroundID must be specified")
	}

	if (rc.BundleLabel != "" && (rc.DeploymentID != "" || rc.PlaygroundID != "")) ||
		(rc.DeploymentID != "" && (rc.BundleLabel != "" || rc.PlaygroundID != "")) ||
		(rc.PlaygroundID != "" && (rc.BundleLabel != "" || rc.DeploymentID != "")) {
		return errors.New("only one of the bundleLabel, deploymentID or playgroundID must be specified")
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
		//nolint:mnd
		if err := os.MkdirAll(dir, 0o764); err != nil {
			return fmt.Errorf("failed to create cache dir %q: %w", dir, err)
		}

		rc.CacheDir = dir
	}

	if rc.Connection != nil {
		util.DeprecationReplacedWarning("storage.bundle.remote.connection section", "hub.connection")
		return errors.New("storage.bundle.remote.connection configuration is no longer supported")
	}

	hubConf, err := hub.GetConf()
	if err != nil {
		return fmt.Errorf("failed to read Cerbos Hub configuration: %w", err)
	}

	rc.Connection = &hubConf.Connection
	return rc.Connection.Validate()
}

func GetConf() (*Conf, error) {
	return GetConfFromWrapper(config.Global())
}

func GetConfFromWrapper(confW *config.Wrapper) (*Conf, error) {
	conf := &Conf{}
	err := confW.GetSection(conf)

	return conf, err
}
