// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package disk

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/util"
)

const DriverName = "disk"

var (
	_ storage.SourceStore  = (*Store)(nil)
	_ storage.Reloadable   = (*Store)(nil)
	_ storage.Subscribable = (*Store)(nil)
)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read disk configuration: %w", err)
		}

		return NewStore(ctx, conf)
	})
}

type Store struct {
	conf   *Conf
	idx    index.Index
	source *auditv1.PolicySource
	*storage.SubscriptionManager
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	dir, err := filepath.Abs(conf.Directory)
	if err != nil {
		return nil, fmt.Errorf("failed to determine absolute path of directory [%s]: %w", conf.Directory, err)
	}

	zap.S().Named("disk.store").Infof("Initializing disk store from %s", dir)

	fsys, err := util.OpenDirectoryFS(dir)
	if err != nil {
		return nil, err
	}

	idx, err := index.Build(ctx, fsys, index.WithSourceAttributes(policy.SourceDriver(DriverName)))
	if err != nil {
		return nil, err
	}

	s := &Store{
		conf:                conf,
		idx:                 idx,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
		source: &auditv1.PolicySource{
			Source: &auditv1.PolicySource_Disk_{
				Disk: &auditv1.PolicySource_Disk{
					Directory: dir,
				},
			},
		},
	}

	metrics.Record(ctx, metrics.StoreLastSuccessfulRefresh(), time.Now().UnixMilli(), metrics.DriverKey(DriverName))
	if conf.WatchForChanges && !util.IsArchiveFile(dir) {
		if err := watchDir(ctx, dir, s.idx, s.SubscriptionManager, defaultCooldownPeriod); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func NewFromIndex(idx index.Index) (*Store, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, err
	}

	return NewFromIndexWithConf(idx, conf), nil
}

func NewFromIndexWithConf(idx index.Index, conf *Conf) *Store {
	return &Store{idx: idx, conf: conf}
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetFirstMatch(_ context.Context, candidates []namer.ModuleID) (*policy.CompilationUnit, error) {
	return s.idx.GetFirstMatch(candidates)
}

func (s *Store) GetAll(ctx context.Context) ([]*policy.CompilationUnit, error) {
	return s.idx.GetAll(ctx)
}

func (s *Store) GetAllMatching(_ context.Context, modIDs []namer.ModuleID) ([]*policy.CompilationUnit, error) {
	return s.idx.GetAllMatching(modIDs)
}

func (s *Store) GetCompilationUnits(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return s.idx.GetCompilationUnits(ids...)
}

func (s *Store) GetDependents(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return s.idx.GetDependents(ids...)
}

func (s *Store) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return s.idx.InspectPolicies(ctx, params.IDs...)
}

func (s *Store) ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	return s.idx.ListPolicyIDs(ctx, params.IDs...)
}

func (s *Store) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return s.idx.ListSchemaIDs(ctx)
}

func (s *Store) LoadSchema(ctx context.Context, url string) (io.ReadCloser, error) {
	return s.idx.LoadSchema(ctx, url)
}

func (s *Store) LoadPolicy(ctx context.Context, file ...string) ([]*policy.Wrapper, error) {
	return s.idx.LoadPolicy(ctx, file...)
}

func (s *Store) RepoStats(ctx context.Context) storage.RepoStats {
	return s.idx.RepoStats(ctx)
}

func (s *Store) Reload(ctx context.Context) error {
	evts, err := s.idx.Reload(ctx)
	if err != nil {
		return fmt.Errorf("failed to reload the index: %w", err)
	}
	s.NotifySubscribers(evts...)

	metrics.Record(ctx, metrics.StoreLastSuccessfulRefresh(), time.Now().UnixMilli(), metrics.DriverKey(DriverName))
	return nil
}

func (s *Store) Source() *auditv1.PolicySource {
	return s.source
}

func (s *Store) Close() error {
	return s.idx.Close()
}
