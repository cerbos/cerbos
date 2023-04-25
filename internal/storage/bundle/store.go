// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
	"go.uber.org/zap"
)

const DriverName = "bundle"

var _ storage.BinaryStore = (*HybridStore)(nil)

var ErrBundleNotLoaded = errors.New("bundle not loaded yet")

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read bundle configuration: %w", err)
		}

		return NewStore(ctx, conf)
	})
}

func NewStore(ctx context.Context, conf *Conf) (storage.BinaryStore, error) {
	log := zap.L().Named(DriverName)

	var local *LocalSource
	var remote *RemoteSource
	var err error

	if conf.Local != nil {
		log.Info("Configuring local bundle source")
		local, err = NewLocalSourceFromConf(ctx, conf)
		if err != nil {
			log.Error("Failed to configure local bundle source", zap.Error(err))
			return nil, err
		}
	}

	if conf.Remote != nil {
		log.Info("Configuring remote bundle source")
		remote, err = NewRemoteSource(conf)
		if err != nil {
			log.Error("Failed to configure remote bundle source", zap.Error(err))
			return nil, err
		}

		if err := remote.Init(ctx); err != nil {
			log.Error("Failed to initialize remote bundle source", zap.Error(err))
			return nil, err
		}
	}

	switch {
	case local != nil && remote != nil:
		return &HybridStore{
			log:             log,
			local:           instrument("local", local),
			remote:          instrument("remote", remote),
			remoteIsHealthy: remote.IsHealthy,
		}, nil
	case local == nil && remote != nil:
		return instrument("remote", remote), nil
	case local != nil && remote == nil:
		return instrument("local", local), nil
	default:
		return nil, ErrNoSource
	}
}

type Source interface {
	SourceKind() string
}

type HybridStore struct {
	log             *zap.Logger
	local           storage.BinaryStore
	remote          storage.BinaryStore
	remoteIsHealthy func() bool
}

func (*HybridStore) Driver() string {
	return DriverName
}

func (hs *HybridStore) withActiveSource() storage.BinaryStore {
	if hs.remoteIsHealthy() {
		return hs.remote
	}

	hs.log.Warn("Switching to local source because remote source is unhealthy")
	return hs.local
}

func (hs *HybridStore) ListPolicyIDs(ctx context.Context, includeDisabled bool) ([]string, error) {
	return hs.withActiveSource().ListPolicyIDs(ctx, includeDisabled)
}

func (hs *HybridStore) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return hs.withActiveSource().ListSchemaIDs(ctx)
}

func (hs *HybridStore) LoadSchema(ctx context.Context, id string) (io.ReadCloser, error) {
	return hs.withActiveSource().LoadSchema(ctx, id)
}

func (hs *HybridStore) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	return hs.withActiveSource().GetPolicySet(ctx, id)
}

func (hs *HybridStore) SourceKind() string {
	return "hybrid"
}
