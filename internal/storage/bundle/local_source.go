// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cloud-api/credentials"
	"github.com/spf13/afero"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

var (
	_ storage.BinaryStore = (*LocalSource)(nil)
	_ storage.Reloadable  = (*LocalSource)(nil)
)

// LocalSource loads a bundle from local disk.
type LocalSource struct {
	bundle  *Bundle
	cleanup func() error
	params  LocalParams
	mu      sync.RWMutex
}

func NewLocalSourceFromConf(_ context.Context, conf *Conf) (*LocalSource, error) {
	if err := conf.Local.setDefaults(); err != nil {
		return nil, err
	}

	return NewLocalSource(LocalParams{
		BundlePath: conf.Local.BundlePath,
		SecretKey:  conf.Credentials.SecretKey,
		TempDir:    conf.Local.TempDir,
	})
}

type LocalParams struct {
	BundlePath string
	TempDir    string
	SecretKey  string
}

func NewLocalSource(params LocalParams) (*LocalSource, error) {
	ls := &LocalSource{params: params}
	if err := ls.loadBundle(); err != nil {
		return nil, err
	}

	return ls, nil
}

func (ls *LocalSource) loadBundle() error {
	workDir, err := os.MkdirTemp(ls.params.TempDir, "cerbos-bundle-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}

	var creds *credentials.Credentials
	if ls.params.SecretKey != "" {
		creds, err = credentials.New("unknown", "unknown", ls.params.SecretKey)
		if err != nil {
			return fmt.Errorf("failed to create credentials: %w", err)
		}
	}

	bundlePath := ls.params.BundlePath
	opts := OpenOpts{
		BundlePath:  bundlePath,
		ScratchFS:   afero.NewBasePathFs(afero.NewOsFs(), workDir),
		Credentials: creds,
	}

	bundle, err := Open(opts)
	if err != nil {
		if err := os.RemoveAll(workDir); err != nil {
			zap.L().Warn("Failed to remove work dir", zap.Error(err), zap.String("workdir", workDir))
		}
		return fmt.Errorf("failed to open bundle %q: %w", bundlePath, err)
	}

	cleanupFn := func() (outErr error) {
		if err := bundle.Release(); err != nil {
			outErr = multierr.Append(outErr, fmt.Errorf("failed to release bundle %q: %w", bundlePath, err))
		}

		if err := os.RemoveAll(workDir); err != nil {
			outErr = multierr.Append(outErr, fmt.Errorf("failed to remove work dir %q: %w", workDir, err))
		}

		return outErr
	}

	ls.mu.Lock()
	prevCleanupFn := ls.cleanup
	ls.cleanup = cleanupFn
	ls.bundle = bundle
	ls.mu.Unlock()

	if prevCleanupFn != nil {
		if err := prevCleanupFn(); err != nil {
			zap.L().Warn("Failed to cleanup previous bundle", zap.Error(err))
		}
	}

	return nil
}

func (ls *LocalSource) Driver() string {
	return DriverName
}

func (ls *LocalSource) ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) (ids []string, err error) {
	ls.mu.RLock()
	ids, err = ls.bundle.ListPolicyIDs(ctx, params)
	ls.mu.RUnlock()
	return ids, err
}

func (ls *LocalSource) ListSchemaIDs(ctx context.Context) (ids []string, err error) {
	ls.mu.RLock()
	ids, err = ls.bundle.ListSchemaIDs(ctx)
	ls.mu.RUnlock()
	return ids, err
}

func (ls *LocalSource) LoadSchema(ctx context.Context, id string) (schema io.ReadCloser, err error) {
	ls.mu.RLock()
	schema, err = ls.bundle.LoadSchema(ctx, id)
	ls.mu.RUnlock()
	return schema, err
}

func (ls *LocalSource) GetPolicySet(ctx context.Context, id namer.ModuleID) (ps *runtimev1.RunnablePolicySet, err error) {
	ls.mu.RLock()
	ps, err = ls.bundle.GetPolicySet(ctx, id)
	ls.mu.RUnlock()
	return ps, err
}

func (ls *LocalSource) Reload(_ context.Context) error {
	return ls.loadBundle()
}

func (ls *LocalSource) Close() error {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if ls.cleanup != nil {
		return ls.cleanup()
	}

	return nil
}

func (ls *LocalSource) SourceKind() string {
	return "local"
}
