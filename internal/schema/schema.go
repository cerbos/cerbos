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
	"net/http"
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

const fileURLScheme = "file"

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
	e.schema, e.err = m.loadSchemaFromStore(ctx, schemaURL)
	if e.err != nil && errors.As(e.err, &notFoundErr) {
		var absolutePath string
		var err error
		if notFoundErr.scheme == fileURLScheme {
			if absolutePath, err = filepath.Abs(schemaURL); err != nil {
				e.err = fmt.Errorf("failed to resolve schema URL %q: %w", schemaURL, err)
			}
		}

		switch {
		case notFoundErr.scheme == fileURLScheme && notFoundErr.fullPath == absolutePath:
			e.err = fmt.Errorf("schema %s doesn't exist", schemaURL)
		case notFoundErr.url != schemaURL:
			e.err = fmt.Errorf("schema %s referenced by %s doesn't exist", notFoundErr.fullPath, schemaURL)
		default:
			e.err = fmt.Errorf("schema %s doesn't exist", notFoundErr.fullPath)
		}
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
	// url is the URL failed to load
	url string
	// scheme is the scheme of the URL without any colons or slashes
	scheme string
	// fullPath is the resolved file system path.
	fullPath string
}

func (e notFoundErr) Error() string {
	return fmt.Sprintf("schema %q does not exist", e.fullPath)
}

func DefaultResolver(loader Loader) Resolver {
	return func(ctx context.Context, path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}

		switch u.Scheme {
		case "", URLScheme:
			return loadCerbosURL(ctx, u, loader)
		case "http", "https":
			return loadHTTPURL(ctx, u)
		case fileURLScheme:
			return loadFileURL(u)
		default:
			return nil, jsonschema.LoaderNotFoundError(path)
		}
	}
}

func loadCerbosURL(ctx context.Context, u *url.URL, loader Loader) (io.ReadCloser, error) {
	relativePath := strings.TrimPrefix(u.Path, "/")
	var pathErr *fs.PathError
	s, err := loader.LoadSchema(ctx, relativePath)
	if err != nil && errors.Is(err, fs.ErrNotExist) && errors.As(err, &pathErr) {
		p := pathErr.Path
		if !strings.HasPrefix(pathErr.Path, util.SchemasDirectory) {
			p = filepath.Join(util.SchemasDirectory, pathErr.Path)
		}

		return nil, &notFoundErr{
			url:      u.String(),
			scheme:   u.Scheme,
			fullPath: p,
		}
	}

	return s, err
}

func loadFileURL(u *url.URL) (io.ReadCloser, error) {
	f := u.Path
	var pathErr *fs.PathError
	if file, err := os.Open(f); err != nil && errors.Is(err, fs.ErrNotExist) && errors.As(err, &pathErr) {
		return nil, &notFoundErr{
			url:      u.String(),
			scheme:   u.Scheme,
			fullPath: pathErr.Path,
		}
	} else {
		return file, nil
	}
}

func loadHTTPURL(ctx context.Context, u *url.URL) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		u.String(),
		http.NoBody,
	)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &notFoundErr{
			url:      u.String(),
			scheme:   u.Scheme,
			fullPath: u.String(),
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status code %d", u.RequestURI(), resp.StatusCode)
	}

	return resp.Body, nil
}
