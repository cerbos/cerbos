// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/disk/index"
)

const DriverName = "disk"

var _ storage.Store = (*Store)(nil)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context) (storage.Store, error) {
		conf := &Conf{}
		if err := config.GetSection(conf); err != nil {
			return nil, err
		}

		return NewStore(ctx, conf)
	})
}

type Store struct {
	idx index.Index
	*storage.SubscriptionManager
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	dir, err := filepath.Abs(conf.Directory)
	if err != nil {
		return nil, fmt.Errorf("failed to determine absolute path of directory [%s]: %w", conf.Directory, err)
	}

	idx, err := index.Build(ctx, os.DirFS(dir), index.WithDiskCache(conf.ScratchDir))
	if err != nil {
		return nil, err
	}

	s := &Store{idx: idx, SubscriptionManager: storage.NewSubscriptionManager(ctx)}
	if conf.WatchForChanges {
		if err := watchDir(ctx, dir, s.idx, s.SubscriptionManager, defaultCooldownPeriod); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func NewFromIndex(idx index.Index) *Store {
	return &Store{idx: idx}
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetCompilationUnits(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return s.idx.GetCompilationUnits(ids...)
}

func (s *Store) GetDependents(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return s.idx.GetDependents(ids...)
}

func (s *Store) GetPolicies(ctx context.Context) ([]*policy.Wrapper, error) {
	return s.idx.GetPolicies(ctx)
}
