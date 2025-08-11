// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package schema

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cerbos/cerbos/internal/util"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"

	// Register the http and https loaders.
	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader"

	"github.com/cerbos/cerbos/internal/cache"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/storage"
)

func NewFromConf(_ context.Context, loader Loader, conf *Conf) Manager {
	if conf.Enforcement == EnforcementNone {
		return NopManager{}
	}

	mgr := &manager{
		StaticManager: StaticManager{
			conf: conf,
			log:  logging.NewLogger("schema"),
		},
		cache:    cache.New[string, *cacheEntry]("schema", conf.CacheSize),
		resolver: DefaultResolver(loader),
	}
	mgr.loader = mgr

	if s, ok := loader.(storage.Subscribable); ok {
		s.Subscribe(mgr)
	}

	return mgr
}

type manager struct {
	StaticManager
	cache    *cache.Cache[string, *cacheEntry]
	resolver Resolver
}

func New(ctx context.Context, loader Loader) (Manager, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to get config section %q: %w", confKey, err)
	}

	return NewFromConf(ctx, loader, conf), nil
}

func NewEphemeral(resolver Resolver) Manager {
	mgr := &manager{
		StaticManager: StaticManager{
			conf: NewConf(EnforcementReject),
			log:  logging.NewLogger("schema"),
		},
		cache:    cache.New[string, *cacheEntry]("schema", defaultCacheSize),
		resolver: resolver,
	}
	mgr.loader = mgr

	return mgr
}

func (m *manager) LoadSchema(ctx context.Context, schemaURL string) (*jsonschema.Schema, error) {
	entry, ok := m.cache.Get(schemaURL)
	if ok {
		return entry.schema, entry.err
	}

	e := &cacheEntry{}
	var notFoundErr *notFoundErr
	if e.schema, e.err = m.loadSchemaFromStore(ctx, schemaURL); e.err != nil && errors.As(e.err, &notFoundErr) {
		parsedSchemaURL, err := url.Parse(schemaURL)
		switch {
		case err != nil:
			e.err = fmt.Errorf("failed to parse URL: %w", err)
		case notFoundErr.Scheme != URLScheme:
			e.err = fmt.Errorf("schema file %q does not exist", schemaURL)
		case strings.TrimPrefix(parsedSchemaURL.Path, "/") != strings.TrimPrefix(notFoundErr.Path, util.SchemasDirectory+string(os.PathSeparator)):
			e.err = fmt.Errorf("schema file %q referenced by the schema does not exist in the store", notFoundErr.Path)
		default:
			e.err = fmt.Errorf("schema file %q does not exist in the store", notFoundErr.Path)
		}

		m.cache.Set(schemaURL, e)
		return e.schema, e.err
	}

	m.cache.Set(schemaURL, e)
	return e.schema, e.err
}

func (m *manager) loadSchemaFromStore(ctx context.Context, schemaURL string) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true
	compiler.LoadURL = func(path string) (io.ReadCloser, error) {
		return m.resolver(ctx, path)
	}

	return compiler.Compile(schemaURL)
}

func (m *manager) SubscriberID() string {
	return "schema.manager"
}

func (m *manager) OnStorageEvent(events ...storage.Event) {
	for _, event := range events {
		//nolint:exhaustive
		switch event.Kind {
		case storage.EventAddOrUpdateSchema:
			cacheKey := fmt.Sprintf("%s:///%s", URLScheme, event.SchemaFile)
			_ = m.cache.Remove(cacheKey)
			m.log.Debug("Handled schema add/update event", logging.String("schema", cacheKey))
		case storage.EventDeleteSchema:
			cacheKey := fmt.Sprintf("%s:///%s", URLScheme, event.SchemaFile)
			_ = m.cache.Remove(cacheKey)
			m.log.Warn("Handled schema delete event", logging.String("schema", cacheKey))
		case storage.EventReload:
			m.cache.Purge()
			m.log.Debug("Handled store reload event")
		}
	}
}

type cacheEntry struct {
	schema *jsonschema.Schema
	err    error
}

type notFoundErr struct {
	Scheme string
	Path   string
}

func (e notFoundErr) Error() string {
	return fmt.Sprintf("schema file %q does not exist in the store", e.Path)
}

func DefaultResolver(loader Loader) Resolver {
	return func(ctx context.Context, path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		if u.Scheme == "" || u.Scheme == URLScheme {
			relativePath := strings.TrimPrefix(u.Path, "/")
			var pathErr *fs.PathError
			s, err := loader.LoadSchema(ctx, relativePath)
			if err != nil && errors.Is(err, fs.ErrNotExist) && errors.As(err, &pathErr) {
				return nil, &notFoundErr{
					Scheme: u.Scheme,
					Path:   filepath.Join(util.SchemasDirectory, pathErr.Path),
				}
			}

			return s, err
		}

		schemaLoader, ok := jsonschema.Loaders[u.Scheme]
		if !ok {
			return nil, jsonschema.LoaderNotFoundError(path)
		}

		s, err := schemaLoader(path)
		var pathErr *fs.PathError
		if err != nil && errors.Is(err, fs.ErrNotExist) && errors.As(err, &pathErr) {
			return nil, &notFoundErr{
				Scheme: u.Scheme,
				Path:   pathErr.Path,
			}
		}

		return s, err
	}
}
