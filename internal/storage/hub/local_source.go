// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/afero"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	cloudapi "github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/credentials"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
)

var (
	_ storage.BinaryStore = (*LocalSource)(nil)
	_ storage.Reloadable  = (*LocalSource)(nil)
)

// LocalSource loads a bundle from local disk.
type LocalSource struct {
	bundle  *Bundle
	cleanup func() error
	source  *auditv1.PolicySource
	*storage.SubscriptionManager
	params LocalParams
	mu     sync.RWMutex
}

func NewLocalSourceFromConf(ctx context.Context, conf *Conf) (*LocalSource, error) {
	if err := conf.Local.setDefaultsForUnsetFields(); err != nil {
		return nil, err
	}

	lp := LocalParams{
		BundlePath: conf.Local.BundlePath,
		TempDir:    conf.Local.TempDir,
		CacheSize:  conf.CacheSize,
	}

	switch {
	case conf.Credentials != nil:
		lp.BundleVersion = cloudapi.Version1
		lp.SecretKey = conf.Credentials.WorkspaceSecret

	case conf.Local != nil && conf.Local.EncryptionKey != "":
		lp.BundleVersion = cloudapi.Version2
		encryptionKey, err := hex.DecodeString(conf.Local.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode encryption key: %w", err)
		}

		lp.EncryptionKey = encryptionKey

	default:
		return nil, fmt.Errorf("encryptionKey or workspaceSecret must be specified")
	}

	return NewLocalSource(ctx, lp)
}

type LocalParams struct {
	BundlePath    string
	TempDir       string
	SecretKey     string
	EncryptionKey []byte
	CacheSize     uint
	BundleVersion cloudapi.Version
}

func NewLocalSource(ctx context.Context, params LocalParams) (*LocalSource, error) {
	if params.CacheSize == 0 {
		params.CacheSize = defaultCacheSize
	}

	var err error
	params.BundlePath, err = filepath.Abs(params.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to determine absolute path of bundle file [%s]: %w", params.BundlePath, err)
	}

	ls := &LocalSource{
		params:              params,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
		source: &auditv1.PolicySource{
			Source: &auditv1.PolicySource_Hub_{
				Hub: &auditv1.PolicySource_Hub{
					Source: &auditv1.PolicySource_Hub_LocalBundle_{
						LocalBundle: &auditv1.PolicySource_Hub_LocalBundle{
							Path: params.BundlePath,
						},
					},
				},
			},
		},
	}

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

	bundlePath := ls.params.BundlePath
	opts := OpenOpts{
		Source:     "local",
		BundlePath: bundlePath,
		ScratchFS:  afero.NewBasePathFs(afero.NewOsFs(), workDir),
		CacheSize:  ls.params.CacheSize,
	}

	var b *Bundle
	switch ls.params.BundleVersion {
	case cloudapi.Version1:
		var creds *credentials.Credentials
		if ls.params.SecretKey != "" {
			creds, err = credentials.New("unknown", "unknown", ls.params.SecretKey)
			if err != nil {
				return fmt.Errorf("failed to create credentials: %w", err)
			}
		}

		opts.Credentials = creds
		if b, err = Open(opts); err != nil {
			if err := os.RemoveAll(workDir); err != nil {
				zap.L().Warn("Failed to remove work dir", zap.Error(err), zap.String("workdir", workDir))
			}

			return fmt.Errorf("failed to open bundle: %w", err)
		}
	case cloudapi.Version2:
		opts.EncryptionKey = ls.params.EncryptionKey
		if b, err = OpenV2(opts); err != nil {
			if err := os.RemoveAll(workDir); err != nil {
				zap.L().Warn("Failed to remove work dir", zap.Error(err), zap.String("workdir", workDir))
			}

			return fmt.Errorf("failed to open bundle v2: %w", err)
		}
	default:
		return fmt.Errorf("unsupported bundle version: %d", ls.params.BundleVersion)
	}

	cleanupFn := func() (outErr error) {
		if err := b.Release(); err != nil {
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
	ls.bundle = b
	ls.mu.Unlock()

	ls.NotifySubscribers(storage.NewReloadEvent())

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

func (ls *LocalSource) GetCacheDuration() time.Duration {
	return 0
}

func (ls *LocalSource) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	if ls.bundle == nil {
		return nil, ErrBundleNotLoaded
	}

	return ls.bundle.InspectPolicies(ctx, params)
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

func (ls *LocalSource) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (ps *runtimev1.RunnablePolicySet, err error) {
	ls.mu.RLock()
	ps, err = ls.bundle.GetFirstMatch(ctx, candidates)
	ls.mu.RUnlock()
	return ps, err
}

func (ls *LocalSource) GetAll(ctx context.Context) (pss []*runtimev1.RunnablePolicySet, err error) {
	ls.mu.RLock()
	pss, err = ls.bundle.GetAll(ctx)
	ls.mu.RUnlock()
	return pss, err
}

func (ls *LocalSource) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) (pss []*runtimev1.RunnablePolicySet, err error) {
	ls.mu.RLock()
	pss, err = ls.bundle.GetAllMatching(ctx, modIDs)
	ls.mu.RUnlock()
	return pss, err
}

func (ls *LocalSource) Reload(_ context.Context) error {
	return ls.loadBundle()
}

func (ls *LocalSource) Source() *auditv1.PolicySource {
	return ls.source
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
