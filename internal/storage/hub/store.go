// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"fmt"
	"io"

	"go.uber.org/multierr"
	"go.uber.org/zap"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const DriverName = "hub"

var _ storage.BinaryStore = (*HybridStore)(nil)

var ErrBundleNotLoaded = errors.New("bundle not loaded yet")

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf, err := GetConfFromWrapper(confW)
		if err != nil {
			return nil, fmt.Errorf("failed to read hub configuration: %w", err)
		}

		return NewStore(ctx, conf)
	})

	storage.RegisterDriver("bundle", func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		util.DeprecationWarning(storage.ConfKey+".bundle", confKey)
		conf := new(Conf)
		if err := confW.Get(storage.ConfKey+".bundle", conf); err != nil {
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

func (hs *HybridStore) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return hs.withActiveSource().InspectPolicies(ctx, params)
}

func (hs *HybridStore) ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	return hs.withActiveSource().ListPolicyIDs(ctx, params)
}

func (hs *HybridStore) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return hs.withActiveSource().ListSchemaIDs(ctx)
}

func (hs *HybridStore) LoadSchema(ctx context.Context, id string) (io.ReadCloser, error) {
	return hs.withActiveSource().LoadSchema(ctx, id)
}

func (hs *HybridStore) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	return hs.withActiveSource().GetFirstMatch(ctx, candidates)
}

func (hs *HybridStore) GetAll(ctx context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	return hs.withActiveSource().GetAll(ctx)
}

func (hs *HybridStore) Subscribe(s storage.Subscriber) {
	hs.local.Subscribe(s)
	hs.remote.Subscribe(s)
}

func (hs *HybridStore) Unsubscribe(s storage.Subscriber) {
	hs.local.Unsubscribe(s)
	hs.remote.Unsubscribe(s)
}

func (hs *HybridStore) SourceKind() string {
	return "hybrid"
}

func (hs *HybridStore) Close() (outErr error) {
	if c, ok := hs.remote.(io.Closer); ok {
		outErr = multierr.Append(outErr, c.Close())
	}

	if c, ok := hs.local.(io.Closer); ok {
		outErr = multierr.Append(outErr, c.Close())
	}

	return outErr
}
