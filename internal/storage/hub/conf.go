// Copyright 2021-2026 Zenauth Ltd.
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
	// CacheSize defines the number of policies to cache in memory.
	CacheSize uint `yaml:"cacheSize" conf:",example=1024"`
}

// LocalSourceConf holds configuration for local bundle store.
type LocalSourceConf struct {
	// BundlePath is the full path to the local bundle file.
	BundlePath string `yaml:"bundlePath" conf:"required,example=/path/to/bundle.crbp"`
	// EncryptionKey is encryption key to decode the bundle. It must be hex encoded.
	EncryptionKey string `yaml:"encryptionKey" conf:",example=9b941a7f43fcade02d1e07bdaca008aedd0310e8804bc465bc44814a2010ecd3"`
	// TempDir is the directory to use for temporary files.
	TempDir string `yaml:"tempDir" conf:",example=${TEMP}"`
}

// RemoteSourceConf holds configuration for remote bundle store.
type RemoteSourceConf struct {
	// DeploymentID to fetch from the server. Mutually exclusive with PlaygroundID
	DeploymentID string `yaml:"deploymentID" conf:",example=TVWD7S5W4V5O"`
	// PlaygroundID to fetch from the server. Mutually exclusive with DeploymentID.
	PlaygroundID string `yaml:"playgroundID" conf:",example=HDUDDWLR6ZVM"`
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
		multierr.AppendInto(&outErr, errors.New("cacheSize must be greater than zero"))
	}

	if err := conf.Local.validate(); err != nil {
		multierr.AppendInto(&outErr, err)
	}

	if err := conf.Remote.validate(); err != nil {
		multierr.AppendInto(&outErr, err)
	}

	return outErr
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

func (rc *RemoteSourceConf) validate() (outErr error) {
	if rc == nil {
		return nil
	}

	if rc.CacheDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("failed to determine cache directory: %w", err)
		}

		dir := filepath.Join(cacheDir, "cerbos-hub")
		const permissions = 0o764
		if err := os.MkdirAll(dir, permissions); err != nil {
			return fmt.Errorf("failed to create cache dir %q: %w", dir, err)
		}

		rc.CacheDir = dir
	}

	if rc.TempDir == "" {
		dir, err := os.MkdirTemp("", "cerbos-hub-*")
		if err != nil {
			return fmt.Errorf("failed to create temporary directory: %w", err)
		}
		rc.TempDir = dir
	}

	if rc.DeploymentID == "" {
		rc.DeploymentID = hub.GetEnv(hub.DeploymentIDKey)
	}

	if rc.PlaygroundID == "" {
		rc.PlaygroundID = hub.GetEnv(hub.PlaygroundIDKey)
	}

	if (rc.DeploymentID == "") == (rc.PlaygroundID == "") {
		multierr.AppendInto(&outErr, errors.New("exactly one of storage.hub.remote.deploymentID or storage.hub.remote.playgroundID must be specified"))
	}

	_, err := hub.GetConf()
	return multierr.Append(outErr, err)
}

func GetConf() (*Conf, error) {
	return GetConfFromWrapper(config.Global())
}

func GetConfFromWrapper(confW *config.Wrapper) (*Conf, error) {
	conf := &Conf{}
	err := confW.GetSection(conf)

	return conf, err
}
