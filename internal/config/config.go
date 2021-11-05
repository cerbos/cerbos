// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/config"
	"go.uber.org/zap"
)

var ErrConfigNotLoaded = errors.New("config not loaded")

var conf = &configHolder{}

type Section interface {
	Key() string
}

type Defaulter interface {
	SetDefaults()
}

type Validator interface {
	Validate() error
}

// Load loads the config file at the given path.
func Load(confFile string, overrides map[string]interface{}) error {
	finfo, err := os.Stat(confFile)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", confFile, err)
	}

	if finfo.IsDir() {
		return fmt.Errorf("config file path is a directory: %s", confFile)
	}

	return doLoad(config.File(confFile), config.Static(overrides))
}

func LoadReader(reader io.Reader) error {
	return doLoad(config.Source(reader))
}

func LoadMap(m map[string]interface{}) error {
	return doLoad(config.Static(m))
}

func doLoad(sources ...config.YAMLOption) error {
	opts := append(sources, config.Expand(os.LookupEnv)) //nolint:gocritic
	provider, err := config.NewYAML(opts...)
	if err != nil {
		if strings.Contains(err.Error(), "couldn't expand environment") {
			return fmt.Errorf("error loading configuration due to unknown environment variable. Config values containing '$' are interpreted as environment variables. Use '$$' to escape literal '$' values: [%w]", err)
		}
		return fmt.Errorf("failed to load config: %w", err)
	}

	conf.replaceProvider(provider)

	return nil
}

// LoadAndWatch automatically reloads configuration if the config file changes.
func LoadAndWatch(ctx context.Context, confFile string, overrides map[string]interface{}) error {
	if err := Load(confFile, overrides); err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to start file watcher: %w", err)
	}

	if err := watcher.Add(confFile); err != nil {
		return fmt.Errorf("failed to add watch to %s: %w", confFile, err)
	}

	go func() {
		defer watcher.Close()

		log := zap.S().Named("config.watch").With("file", confFile)
		log.Info("Watching config file for changes")

		for {
			select {
			case <-ctx.Done():
				log.Info("Stopping config file watch")

				return
			case event, ok := <-watcher.Events:
				if !ok {
					log.Info("Stopping config file watch")
					return
				}

				switch {
				case event.Op&fsnotify.Create == fsnotify.Create:
					fallthrough
				case event.Op&fsnotify.Write == fsnotify.Write:
					if err := Load(confFile, overrides); err != nil {
						log.Warnw("Failed to reload config file", "error", err)
					} else {
						log.Info("Config file reloaded")
					}
				case event.Op&fsnotify.Remove == fsnotify.Remove:
					log.Warn("Config file removed")
				case event.Op&fsnotify.Rename == fsnotify.Rename:
					log.Warn("Config file renamed")
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					log.Info("Stopping config file watch")
					return
				}

				log.Warnw("Error watching config file", "error", err)
			}
		}
	}()

	return nil
}

// Get populates out with the configuration at the given key.
// Populate out with default values before calling this function to ensure sane defaults if there are any.
func Get(key string, out interface{}) error {
	return conf.Get(key, out)
}

// GetSection populates a config section.
func GetSection(section Section) error {
	return conf.Get(section.Key(), section)
}

type configHolder struct {
	mu       sync.RWMutex
	provider config.Provider
}

func (ch *configHolder) Get(key string, out interface{}) error {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if ch.provider == nil {
		if d, ok := out.(Defaulter); ok {
			d.SetDefaults()
			return nil
		}

		return ErrConfigNotLoaded
	}

	// set defaults if any are specified
	if d, ok := out.(Defaulter); ok {
		d.SetDefaults()
	}

	if err := ch.provider.Get(key).Populate(out); err != nil {
		return err
	}

	// validate if a validate function is available
	if v, ok := out.(Validator); ok {
		return v.Validate()
	}

	return nil
}

func (ch *configHolder) replaceProvider(provider config.Provider) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.provider = provider
}
