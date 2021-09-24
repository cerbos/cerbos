// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/djherbis/times"

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
	config *Conf
	idx    index.Index
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

	c := *conf
	s := &Store{idx: idx, SubscriptionManager: storage.NewSubscriptionManager(ctx), config: &c}
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
	policies, err := s.idx.GetPolicies(ctx)
	if err != nil {
		return nil, err
	}

	if s.config.Directory == "" {
		return policies, nil
	}

	for _, p := range policies {
		fi, err := times.Stat(filepath.Join(s.config.Directory, p.Metadata.SourceFile))
		if err != nil {
			return nil, fmt.Errorf("could not stat file: %w", err)
		}

		if p.Policy.Metadata.Annotations == nil {
			p.Policy.Metadata.Annotations = make(map[string]string)
		}
		p.Policy.Metadata.Annotations["created_at"] = fi.BirthTime().Format(time.RFC3339)
	}

	return policies, nil
}
