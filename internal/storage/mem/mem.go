// Copyright 2021 Zenauth Ltd.

package mem

import (
	"context"

	"github.com/spf13/afero"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/storage/common"
	"github.com/cerbos/cerbos/internal/storage/disk"
)

const DriverName = "mem"

type Store struct {
	*common.Notifier
	index disk.Index
}

func NewStore(ctx context.Context, fs afero.Fs) (*Store, error) {
	idx, err := disk.BuildIndex(ctx, afero.NewIOFS(fs), ".")
	if err != nil {
		return nil, err
	}

	return &Store{index: idx, Notifier: common.NewNotifier()}, nil
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetAllPolicies(ctx context.Context) <-chan *compile.Unit {
	return s.index.GetAllPolicies(ctx)
}
