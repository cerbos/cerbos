// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/cerbos/cerbos/internal/util"

	"github.com/cerbos/cloud-api/credentials"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/spf13/afero"
	"github.com/spf13/afero/zipfs"
	"go.uber.org/zap"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/cache"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/inspect"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	manifestFileName = "MANIFEST"
	policyDir        = "policies/"
	schemaDir        = "_schemas/"
)

type cleanupFn func() error

type OpenOpts struct {
	Credentials *credentials.Credentials
	ScratchFS   afero.Fs
	BundlePath  string
	Source      string
	CacheSize   uint
}

type Bundle struct {
	bundleFS afero.Fs
	manifest *bundlev1.Manifest
	cache    *cache.Cache[namer.ModuleID, cacheEntry]
	cleanup  cleanupFn
	path     string
}

type cacheEntry struct {
	policySet *runtimev1.RunnablePolicySet
	err       error
}

func Open(opts OpenOpts) (*Bundle, error) {
	logger := zap.L().Named(DriverName).With(zap.String("path", opts.BundlePath))
	logger.Info("Opening bundle")

	decryptedPath, size, err := decryptBundle(opts, logger)
	if err != nil {
		return nil, err
	}

	zipFS, cleanup, err := archiveToFS(opts, decryptedPath, size, logger)
	if err != nil {
		return nil, err
	}

	logger.Debug("Reading manifest")
	manifest, err := loadManifest(zipFS)
	if err != nil {
		_ = cleanup()
		return nil, err
	}

	logger.Info("Bundle opened", zap.String("identifier", manifest.Meta.Identifier))

	return &Bundle{
		path:     decryptedPath,
		manifest: manifest,
		bundleFS: zipFS,
		cleanup:  cleanup,
		cache:    cache.New[namer.ModuleID, cacheEntry]("bundle", opts.CacheSize, metrics.SourceKey(opts.Source)),
	}, nil
}

func decryptBundle(opts OpenOpts, logger *zap.Logger) (string, int64, error) {
	input, err := os.Open(opts.BundlePath)
	if err != nil {
		logger.Debug("Failed to open bundle", zap.Error(err))
		return "", 0, fmt.Errorf("failed to open bundle at path %q: %w", opts.BundlePath, err)
	}
	defer input.Close()

	var decrypted io.Reader
	if opts.Credentials == nil {
		decrypted = input
	} else {
		logger.Debug("Decrypting bundle")
		decrypted, err = opts.Credentials.Decrypt(input)
		if err != nil {
			logger.Debug("Failed to decrypt bundle", zap.Error(err))
			return "", 0, fmt.Errorf("failed to decrypt bundle: %w", err)
		}
	}

	afs := &afero.Afero{Fs: opts.ScratchFS}
	outFile, err := afs.TempFile(".", "bundle-*")
	if err != nil {
		logger.Debug("Failed to create temporary file", zap.Error(err))
		return "", 0, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer outFile.Close()

	fileName := outFile.Name()
	logger.Debug("Writing bundle archive", zap.String("archive", fileName))
	size, err := io.Copy(outFile, decrypted)
	if err != nil {
		logger.Debug("Failed to write bundle archive", zap.Error(err))
		return "", 0, fmt.Errorf("failed to write bundle archive: %w", err)
	}

	return fileName, size, nil
}

func archiveToFS(opts OpenOpts, archivePath string, archiveSize int64, logger *zap.Logger) (afero.Fs, cleanupFn, error) {
	log := logger.With(zap.String("archive", archivePath))
	afs := &afero.Afero{Fs: opts.ScratchFS}
	archiveIn, err := afs.Open(archivePath)
	if err != nil {
		log.Debug("Failed to open bundle archive", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to open bundle archive %q: %w", archivePath, err)
	}

	log.Debug("Reading bundle archive")
	zipIn, err := zip.NewReader(archiveIn, archiveSize)
	if err != nil {
		_ = archiveIn.Close()
		log.Debug("Failed to read bundle archive", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to open archive: %w", err)
	}

	cleanup := func() error {
		log.Debug("Closing bundle archive", zap.Error(err))
		if err := archiveIn.Close(); err != nil {
			log.Debug("Failed to close bundle archive", zap.Error(err))
			return err
		}

		// Because we use random strings to avoid a clash, clean up the file
		log.Debug("Removing bundle archive", zap.Error(err))
		if err := opts.ScratchFS.Remove(archivePath); err != nil {
			log.Warn("Failed to remove temporary bundle archive "+archivePath, zap.Error(err))
			return err
		}

		return nil
	}

	return zipfs.New(zipIn), cleanup, nil
}

func loadManifest(bundleFS afero.Fs) (*bundlev1.Manifest, error) {
	mf, err := bundleFS.Open(manifestFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}
	defer mf.Close()

	manifestBytes, err := io.ReadAll(mf)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest bytes: %w", err)
	}

	manifest := &bundlev1.Manifest{}
	if err := manifest.UnmarshalVT(manifestBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	return manifest, nil
}

func (b *Bundle) GetFirstMatch(_ context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	for _, id := range candidates {
		cached, ok := b.cache.Get(id)
		if ok {
			return cached.policySet, cached.err
		}

		idHex := id.HexStr()
		fileName := policyDir + idHex

		if _, err := b.bundleFS.Stat(fileName); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}

			return nil, fmt.Errorf("failed to stat policy %s: %w", idHex, err)
		}

		policySet, err := b.loadPolicySet(idHex, fileName)
		b.cache.Set(id, cacheEntry{policySet: policySet, err: err})
		return policySet, err
	}

	return nil, nil
}

// GetAll attempts to retrieve all policies from the passed modIDs. It will not fall back up the scope chain if a
// specific module is missing and only returns those modules that exist.
func (b *Bundle) GetAll(_ context.Context, modIDs []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	res := []*runtimev1.RunnablePolicySet{}
	for _, id := range modIDs {
		cached, ok := b.cache.Get(id)
		if ok {
			res = append(res, cached.policySet)
			continue
		}

		idHex := id.HexStr()
		fileName := policyDir + idHex

		if _, err := b.bundleFS.Stat(fileName); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}

			return nil, fmt.Errorf("failed to stat policy %s: %w", idHex, err)
		}

		policySet, err := b.loadPolicySet(idHex, fileName)
		if policySet != nil {
			b.cache.Set(id, cacheEntry{policySet: policySet, err: err})
			res = append(res, policySet)
		}
	}

	return res, nil
}

func (b *Bundle) loadPolicySet(idHex, fileName string) (*runtimev1.RunnablePolicySet, error) {
	f, err := b.bundleFS.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy %s: %w", idHex, err)
	}
	defer f.Close()

	policyBytes, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy %s: %w", idHex, err)
	}

	rps := &runtimev1.RunnablePolicySet{}
	if err := rps.UnmarshalVT(policyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", idHex, err)
	}

	if err := compile.MigrateCompiledPolicies(rps); err != nil {
		return nil, err
	}

	return rps, nil
}

func (b *Bundle) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	var policyIDs []string
	if len(params.IDs) == 0 {
		var err error
		if policyIDs, err = b.ListPolicyIDs(ctx, params); err != nil {
			return nil, fmt.Errorf("failed to list policies: %w", err)
		}
	} else {
		policyIDs = params.IDs
	}

	ins := inspect.PolicySets()
	for _, policyID := range policyIDs {
		id := namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(policyID))
		idHex := id.HexStr()
		fileName := policyDir + idHex

		pset, err := b.loadPolicySet(idHex, fileName)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy %s: %w", policyID, err)
		}

		if err := ins.Inspect(pset); err != nil {
			return nil, fmt.Errorf("failed to inspect policy %s: %w", policyID, err)
		}
	}

	return ins.Results()
}

func (b *Bundle) ListPolicyIDs(_ context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	filteredSize := len(b.manifest.PolicyIndex)
	var ss util.StringSet
	if len(params.IDs) > 0 {
		ss = util.ToStringSet(params.IDs)
		filteredSize = len(ss)
	}

	output := make([]string, 0, filteredSize)
	for fqn := range b.manifest.PolicyIndex {
		if len(params.IDs) > 0 {
			if ss.Contains(fqn) {
				output = append(output, namer.PolicyKeyFromFQN(fqn))
			}
		} else {
			output = append(output, namer.PolicyKeyFromFQN(fqn))
		}
	}

	return output, nil
}

func (b *Bundle) ListSchemaIDs(_ context.Context) ([]string, error) {
	output := make([]string, len(b.manifest.Schemas))
	for i, s := range b.manifest.Schemas {
		output[i] = strings.TrimPrefix(s, schemaDir)
	}

	return output, nil
}

func (b *Bundle) LoadSchema(_ context.Context, path string) (io.ReadCloser, error) {
	fullPath := schemaDir + path

	f, err := b.bundleFS.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load schema %s: %w", path, err)
	}

	// TODO(cell): Should we write the schema to scratch dir and create a reader for that instead?
	return f, nil
}

func (b *Bundle) Release() error {
	return b.Close()
}

func (b *Bundle) Close() error {
	return b.cleanup()
}
