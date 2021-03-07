package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/config"
	"go.uber.org/zap"
)

var ErrConfigNotLoaded = errors.New("config not loaded")

var conf *configHolder = &configHolder{}

type Validator interface {
	Validate() error
}

// Load loads the config file at the given path.
func Load(confFile string) error {
	finfo, err := os.Stat(confFile)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", confFile, err)
	}

	if finfo.IsDir() {
		return fmt.Errorf("config file path is a directory: %s", confFile)
	}

	provider, err := config.NewYAML(config.File(confFile), config.Expand(os.LookupEnv))
	if err != nil {
		return fmt.Errorf("failed to create config provider: %w", err)
	}

	conf.replaceProvider(provider)

	return nil
}

// LoadAndWatch automatically reloads configuration if the config file changes.
func LoadAndWatch(ctx context.Context, confFile string) error {
	if err := Load(confFile); err != nil {
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
					if err := Load(confFile); err != nil {
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

type configHolder struct {
	mu       sync.RWMutex
	provider config.Provider
}

func (ch *configHolder) Get(key string, out interface{}) error {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if ch.provider == nil {
		return ErrConfigNotLoaded
	}

	if err := ch.provider.Get(key).Populate(out); err != nil {
		return err
	}

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
